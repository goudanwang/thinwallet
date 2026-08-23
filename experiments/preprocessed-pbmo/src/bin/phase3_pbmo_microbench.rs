use anyhow::{anyhow, Result};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use hmac::{Hmac, Mac};
use preprocessed_pbmo::{
    basis_digest, derive_mask_scalar, DomainMetadata, RelationShape, SoftwareTokenStoreKeyProvider,
    Token, TokenBinding, BACKEND_REVISION,
};
use rand::SeedableRng;
use serde::Serialize;
use sha2::Sha256;
use std::fs::{self, File};
use std::hint::black_box;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Instant;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct Sample {
    operation: String,
    repetition: usize,
    elapsed_ns: u64,
    peak_vmhwm_kib: Option<u64>,
}

fn proc_kib(name: &str) -> Option<u64> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            let (field, rest) = line.split_once(':')?;
            (field == name)
                .then(|| rest.split_whitespace().next()?.parse::<u64>().ok())
                .flatten()
        })
}

fn measure(
    samples: &mut Vec<Sample>,
    operation: &str,
    repetitions: usize,
    mut function: impl FnMut() -> Result<()>,
) -> Result<()> {
    function()?;
    for repetition in 0..repetitions {
        let started = Instant::now();
        function()?;
        samples.push(Sample {
            operation: operation.to_string(),
            repetition,
            elapsed_ns: started.elapsed().as_nanos() as u64,
            peak_vmhwm_kib: proc_kib("VmHWM"),
        });
    }
    Ok(())
}

fn bases(m: usize) -> Vec<RistrettoPoint> {
    (0..m)
        .map(|index| RISTRETTO_BASEPOINT_POINT * Scalar::from((index + 1) as u64))
        .collect()
}

fn scalars(count: usize, salt: u64) -> Vec<Scalar> {
    (0..count)
        .map(|index| Scalar::from((index as u64 + 1) * 17 + salt))
        .collect()
}

fn mask_metadata(q: usize, m: usize, basis: &[RistrettoPoint]) -> DomainMetadata {
    DomainMetadata {
        token_id: [3; 16],
        basis_digest: basis_digest(basis),
        backend_revision: BACKEND_REVISION.into(),
        logical_commitment_id: "phase3-microbench".into(),
        relation_shape: "q-by-m".into(),
        q: q as u32,
        m: m as u32,
    }
}

fn masked_matrix(q: usize, m: usize, seed: &[u8; 32], metadata: &DomainMetadata) -> Vec<Scalar> {
    (0..q)
        .flat_map(|row| {
            (0..m).map(move |col| {
                Scalar::from((row * m + col + 1) as u64)
                    + derive_mask_scalar(seed, metadata, row as u32, col as u32, 0)
            })
        })
        .collect()
}

fn server_outputs(
    matrix: &[Scalar],
    basis: &[RistrettoPoint],
    q: usize,
    m: usize,
) -> Vec<RistrettoPoint> {
    matrix
        .chunks_exact(m)
        .take(q)
        .map(|row| RistrettoPoint::vartime_multiscalar_mul(row, basis))
        .collect()
}

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let value = |flag: &str| -> Result<String> {
        let index = args
            .iter()
            .position(|argument| argument == flag)
            .ok_or_else(|| anyhow!("missing {flag}"))?;
        args.get(index + 1)
            .cloned()
            .ok_or_else(|| anyhow!("missing value for {flag}"))
    };
    let workload = value("--workload")?;
    let q = value("--q")?.parse::<usize>()?;
    let m = value("--m")?.parse::<usize>()?;
    let repetitions = value("--repetitions")
        .unwrap_or_else(|_| "10".into())
        .parse::<usize>()?;
    let output = PathBuf::from(value("--output")?);
    let temp_root = PathBuf::from(value("--temp-root")?);
    fs::create_dir_all(&temp_root)?;
    if q == 0 || m == 0 {
        return Err(anyhow!("q and m must be positive"));
    }

    let basis = bases(m);
    let row = scalars(m, 11);
    let matrix = scalars(q * m, 23);
    let rho = scalars(q, 37);
    let seed = [9u8; 32];
    let metadata = mask_metadata(q, m, &basis);
    let masked = masked_matrix(q, m, &seed, &metadata);
    let outputs = server_outputs(&masked, &basis, q, m);
    let corrections = server_outputs(
        &(0..q)
            .flat_map(|r| {
                (0..m).map({
                    let metadata = metadata.clone();
                    move |c| derive_mask_scalar(&seed, &metadata, r as u32, c as u32, 0)
                })
            })
            .collect::<Vec<_>>(),
        &basis,
        q,
        m,
    );
    let encoded_scalars = masked
        .iter()
        .flat_map(|scalar| scalar.to_bytes())
        .collect::<Vec<_>>();
    let encoded_points = outputs
        .iter()
        .flat_map(|point| point.compress().to_bytes())
        .collect::<Vec<_>>();
    let spool = temp_root.join(format!("{workload}-{q}x{m}.spool"));
    let mut samples = Vec::new();

    measure(&mut samples, "one_native_m_term_msm", repetitions, || {
        black_box(RistrettoPoint::vartime_multiscalar_mul(&row, &basis));
        Ok(())
    })?;
    measure(&mut samples, "q_native_m_term_msms", repetitions, || {
        black_box(server_outputs(&matrix, &basis, q, m));
        Ok(())
    })?;
    measure(&mut samples, "generate_one_mask_row", repetitions, || {
        let generated = (0..m)
            .map(|col| derive_mask_scalar(&seed, &metadata, 0, col as u32, 0))
            .collect::<Vec<_>>();
        black_box(generated);
        Ok(())
    })?;
    measure(&mut samples, "generate_q_mask_rows", repetitions, || {
        black_box(masked_matrix(q, m, &seed, &metadata));
        Ok(())
    })?;
    measure(
        &mut samples,
        "scalar_canonical_encoding",
        repetitions,
        || {
            black_box(matrix.iter().map(Scalar::to_bytes).collect::<Vec<_>>());
            Ok(())
        },
    )?;
    measure(
        &mut samples,
        "request_framing_and_authentication",
        repetitions,
        || {
            let mut mac = HmacSha256::new_from_slice(&[0x42; 32]).unwrap();
            mac.update(&(q as u32).to_le_bytes());
            mac.update(&(m as u32).to_le_bytes());
            mac.update(&encoded_scalars);
            black_box(mac.finalize().into_bytes());
            Ok(())
        },
    )?;
    measure(&mut samples, "request_spool_write", repetitions, || {
        let mut file = File::create(&spool)?;
        file.write_all(&encoded_scalars)?;
        file.sync_data()?;
        Ok(())
    })?;
    measure(&mut samples, "request_spool_replay", repetitions, || {
        let mut bytes = Vec::new();
        File::open(&spool)?.read_to_end(&mut bytes)?;
        black_box(bytes);
        Ok(())
    })?;
    measure(&mut samples, "aggregate_coefficients", repetitions, || {
        let mut aggregate = vec![Scalar::ZERO; m];
        for (coefficient, row) in rho.iter().zip(masked.chunks_exact(m)) {
            for (target, value) in aggregate.iter_mut().zip(row) {
                *target += coefficient * value;
            }
        }
        black_box(aggregate);
        Ok(())
    })?;
    let aggregate_scalars = (0..m)
        .map(|column| {
            rho.iter()
                .zip(masked.chunks_exact(m))
                .map(|(coefficient, row)| coefficient * row[column])
                .sum()
        })
        .collect::<Vec<Scalar>>();
    measure(&mut samples, "aggregate_m_term_msm", repetitions, || {
        black_box(RistrettoPoint::vartime_multiscalar_mul(
            &aggregate_scalars,
            &basis,
        ));
        Ok(())
    })?;
    measure(
        &mut samples,
        "q_point_linear_combination",
        repetitions,
        || {
            black_box(RistrettoPoint::vartime_multiscalar_mul(&rho, &outputs));
            Ok(())
        },
    )?;
    measure(&mut samples, "q_point_subtractions", repetitions, || {
        black_box(
            outputs
                .iter()
                .zip(&corrections)
                .map(|(output, correction)| output - correction)
                .collect::<Vec<_>>(),
        );
        Ok(())
    })?;
    measure(&mut samples, "response_decode", repetitions, || {
        let decoded = encoded_points
            .chunks_exact(32)
            .map(|bytes| {
                let mut raw = [0u8; 32];
                raw.copy_from_slice(bytes);
                CompressedRistretto(raw)
                    .decompress()
                    .ok_or_else(|| anyhow!("decode"))
            })
            .collect::<Result<Vec<_>>>()?;
        black_box(decoded);
        Ok(())
    })?;
    let online = || {
        let masked = masked_matrix(q, m, &seed, &metadata);
        let server = server_outputs(&masked, &basis, q, m);
        let recovered = server
            .iter()
            .zip(&corrections)
            .map(|(point, correction)| point - correction)
            .collect::<Vec<_>>();
        black_box(recovered);
        Ok(())
    };
    measure(
        &mut samples,
        "complete_pbmo_online_client_path_with_preexisting_token",
        repetitions,
        || online(),
    )?;
    measure(&mut samples, "decode_q_by_m_scalars", repetitions, || {
        let decoded = encoded_scalars
            .chunks_exact(32)
            .map(|bytes| {
                let mut raw = [0u8; 32];
                raw.copy_from_slice(bytes);
                Option::<Scalar>::from(Scalar::from_canonical_bytes(raw))
                    .ok_or_else(|| anyhow!("non-canonical scalar"))
            })
            .collect::<Result<Vec<_>>>()?;
        black_box(decoded);
        Ok(())
    })?;
    measure(&mut samples, "q_m_term_msms", repetitions, || {
        black_box(server_outputs(&masked, &basis, q, m));
        Ok(())
    })?;
    measure(&mut samples, "response_encoding", repetitions, || {
        black_box(
            outputs
                .iter()
                .map(|point| point.compress().to_bytes())
                .collect::<Vec<_>>(),
        );
        Ok(())
    })?;
    measure(
        &mut samples,
        "complete_pbmo_server_path",
        repetitions,
        || {
            let decoded = encoded_scalars
                .chunks_exact(32)
                .map(|bytes| {
                    let mut raw = [0u8; 32];
                    raw.copy_from_slice(bytes);
                    Option::<Scalar>::from(Scalar::from_canonical_bytes(raw))
                        .ok_or_else(|| anyhow!("non-canonical scalar"))
                })
                .collect::<Result<Vec<_>>>()?;
            let points = server_outputs(&decoded, &basis, q, m);
            black_box(
                points
                    .iter()
                    .map(|point| point.compress().to_bytes())
                    .collect::<Vec<_>>(),
            );
            Ok(())
        },
    )?;
    measure(
        &mut samples,
        "complete_pbmo_online_request",
        repetitions,
        || online(),
    )?;
    measure(
        &mut samples,
        "local_native_commitment_call",
        repetitions,
        || {
            black_box(server_outputs(&matrix, &basis, q, m));
            Ok(())
        },
    )?;
    let binding = TokenBinding {
        basis_digest: basis_digest(&basis),
        backend_revision: BACKEND_REVISION.into(),
        relation_shape: RelationShape {
            relation_id: workload.clone(),
            logical_commitment_id: "phase3-microbench".into(),
            layout_version: "q-by-m".into(),
        },
        q: q as u32,
        m: m as u32,
    };
    measure(
        &mut samples,
        "complete_pbmo_total_cost_including_one_token_generation",
        repetitions,
        || {
            let token = Token::generate_with_material(binding.clone(), &basis, [3; 16], seed)
                .map_err(|error| anyhow!(error.to_string()))?;
            let mut rng = rand::rngs::StdRng::seed_from_u64(7);
            black_box(
                token
                    .encode(
                        &SoftwareTokenStoreKeyProvider::new("software-test-key-v1", [0x42; 32]),
                        &mut rng,
                    )
                    .map_err(|error| anyhow!(error.to_string()))?,
            );
            online()
        },
    )?;
    let _ = fs::remove_file(spool);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        output,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "thinwallet-phase3-pbmo-microbench-v1",
            "workload": workload,
            "q": q,
            "m": m,
            "repetitions": repetitions,
            "warmups_per_operation": 1,
            "implementation_scope": "in-process PBMO protocol core; network timing is measured by the four-mode runner",
            "samples": samples,
        }))?,
    )?;
    Ok(())
}
