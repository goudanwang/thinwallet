use anyhow::{anyhow, Result};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use preprocessed_pbmo::{
    basis_digest, Corruption, NativeLocalPbmoProvider, PbmoContext, PbmoMetrics,
    PreprocessedMaliciousPbmoProvider, PreprocessedPbmoProvider,
    PreprocessedSemihonestPbmoProvider, RelationShape, SoftwareTokenStoreKeyProvider, Token,
    TokenBinding, TokenState, BACKEND_REVISION, PROTOCOL_VERSION,
};
use rand::{rngs::StdRng, SeedableRng};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs, time::Instant};

#[derive(Serialize)]
struct ModeResult {
    mode: String,
    elapsed_ms: f64,
    outputs_sha256: String,
    exact_ordered_outputs: bool,
    metrics: PbmoMetrics,
}

fn token(q: usize, m: usize, bases: &[RistrettoPoint], suffix: u8) -> Result<Token> {
    let binding = TokenBinding {
        basis_digest: basis_digest(bases),
        backend_revision: BACKEND_REVISION.into(),
        relation_shape: RelationShape {
            relation_id: "v4b-batched-pedersen-vector-commitments".into(),
            logical_commitment_id: "pedersen.shared-basis.ordered-outputs".into(),
            layout_version: "second-application-v1".into(),
        },
        q: q as u32,
        m: m as u32,
    };
    let mut id = [0x42; 16];
    id[15] = suffix;
    let mut seed = [0x24; 32];
    seed[31] = suffix;
    let mut token = Token::generate_with_material(binding, bases, id, seed)
        .map_err(|error| anyhow!(error.to_string()))?;
    token.state = TokenState::Reserved;
    Ok(token)
}

fn context(
    q: usize,
    _m: usize,
    bases: &[RistrettoPoint],
    token_id: Option<[u8; 16]>,
    mode: &str,
) -> PbmoContext {
    PbmoContext {
        protocol_version: PROTOCOL_VERSION,
        session_id: format!("v4b-second-{mode}"),
        proof_id: "pedersen-batch-001".into(),
        token_id,
        logical_commitment_id: "pedersen.shared-basis.ordered-outputs".into(),
        basis_digest: basis_digest(bases),
        backend_revision: BACKEND_REVISION.into(),
        relation_shape: "v4b-batched-pedersen-vector-commitments:second-application-v1".into(),
        expected_chunks: q as u32,
    }
}

fn digest_outputs(outputs: &[RistrettoPoint]) -> String {
    let mut hasher = Sha256::new();
    for point in outputs {
        hasher.update(point.compress().as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn run_provider(
    name: &str,
    provider: &mut dyn PreprocessedPbmoProvider,
    vectors: &[Vec<Scalar>],
    bases: &[RistrettoPoint],
    token_id: Option<[u8; 16]>,
    expected: Option<&[RistrettoPoint]>,
) -> Result<(Vec<RistrettoPoint>, ModeResult)> {
    let q = vectors.len();
    let m = bases.len();
    let start = Instant::now();
    let mut session = provider
        .begin(context(q, m, bases, token_id, name), q, m)
        .map_err(|error| anyhow!(error.to_string()))?;
    for (row, scalars) in vectors.iter().enumerate() {
        provider
            .push_private_row_chunk(&mut session, row, 0..m, scalars)
            .map_err(|error| anyhow!(error.to_string()))?;
    }
    let outputs = provider
        .finalize(session)
        .map_err(|error| anyhow!(error.to_string()))?;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let exact = expected.map(|points| points == outputs).unwrap_or(true);
    let metrics = provider
        .last_metrics()
        .cloned()
        .ok_or_else(|| anyhow!("missing PBMO metrics"))?;
    Ok((
        outputs.clone(),
        ModeResult {
            mode: name.into(),
            elapsed_ms,
            outputs_sha256: digest_outputs(&outputs),
            exact_ordered_outputs: exact,
            metrics,
        },
    ))
}

fn main() -> Result<()> {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../credential_workloads/results/second_pbmo_application.json".into());
    let q = 32usize;
    let m = 128usize;
    let bases: Vec<_> = (1..=m)
        .map(|index| Scalar::from(index as u64) * RISTRETTO_BASEPOINT_POINT)
        .collect();
    let vectors: Vec<Vec<_>> = (0..q)
        .map(|row| {
            (0..m)
                .map(|column| Scalar::from((1 + row * m + column) as u64))
                .collect()
        })
        .collect();

    let token_semi = token(q, m, &bases, 1)?;
    let token_malicious = token(q, m, &bases, 2)?;
    let token_corrupt = token(q, m, &bases, 3)?;
    let token_id_semi = token_semi.token_id;
    let token_id_malicious = token_malicious.token_id;
    let token_id_corrupt = token_corrupt.token_id;
    let mut encoded_token = token(q, m, &bases, 4)?;
    encoded_token.creation_epoch = 0;
    let mut rng = StdRng::seed_from_u64(0x5634_4202);
    let token_bytes = encoded_token
        .encode(
            &SoftwareTokenStoreKeyProvider::new("software-test-key-v1", [0x42; 32]),
            &mut rng,
        )
        .map_err(|error| anyhow!(error.to_string()))?;

    let mut native = NativeLocalPbmoProvider::new(bases.clone());
    let (expected, native_result) =
        run_provider("native", &mut native, &vectors, &bases, None, None)?;
    let mut semi = PreprocessedSemihonestPbmoProvider::new(bases.clone(), token_semi);
    let (_, semi_result) = run_provider(
        "semi",
        &mut semi,
        &vectors,
        &bases,
        Some(token_id_semi),
        Some(&expected),
    )?;
    let mut malicious = PreprocessedMaliciousPbmoProvider::new(bases.clone(), token_malicious);
    let (_, malicious_result) = run_provider(
        "malicious",
        &mut malicious,
        &vectors,
        &bases,
        Some(token_id_malicious),
        Some(&expected),
    )?;

    let mut corrupted = PreprocessedMaliciousPbmoProvider::new(bases.clone(), token_corrupt)
        .with_corruption(Corruption::OneOutput);
    let corruption_rejected = run_provider(
        "malicious-corrupted",
        &mut corrupted,
        &vectors,
        &bases,
        Some(token_id_corrupt),
        Some(&expected),
    )
    .is_err();

    let passed = semi_result.exact_ordered_outputs
        && malicious_result.exact_ordered_outputs
        && corruption_rejected;
    let report = serde_json::json!({
        "classification": if passed { "PBMO_SECOND_APPLICATION_PASS" } else { "PHASE_V4B_SECOND_APPLICATION_BLOCKED" },
        "application": "batched Pedersen-style vector commitments outside libspartan proving path",
        "q": q,
        "m": m,
        "shared_public_basis_points": m,
        "independent_private_vectors": q,
        "ordered_commitment_outputs": q,
        "token_size_bytes": token_bytes.len(),
        "correction_point_count": q,
        "native": native_result,
        "semi_honest": semi_result,
        "malicious": malicious_result,
        "malicious_corruption_rejected": corruption_rejected,
        "proof_output_compatibility": "all modes return the exact same ordered compressed Ristretto commitments",
        "integration_location": "src/bin/phase_v4b_second_pbmo.rs; no libspartan prover call site",
    });
    if let Some(parent) = std::path::Path::new(&output).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    println!("{output}");
    if passed {
        Ok(())
    } else {
        Err(anyhow!("second PBMO application failed"))
    }
}
