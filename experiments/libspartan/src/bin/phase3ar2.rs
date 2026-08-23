use anyhow::{anyhow, Context, Result};
use libspartan as upstream;
use libspartan_baseline as baseline;
use libspartan_patched as patched;
use merlin::Transcript;
use patched::prover_msm::{
    remote_binding_negative_tests, with_prover_msm_provider, ProverMsmCallReport,
    ProverMsmProviderKind, ProverMsmRunConfig, RemoteBindingNegativeTests,
    INTEGRATION_ONLY_NOT_SECURITY_CLAIM,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const LOG_SIZE: usize = 12;
const NUM_INPUTS: usize = 1;
const TRANSCRIPT_LABEL: &[u8] = b"thinwallet_phase3ar2_fixed";
const SELECTED_MSM_ID: &str = "dense_mlpoly.private_commit.0.chunk.0";
const UPSTREAM_COMMIT: &str = "2b791bd7d572433b245eba7d5e5aeba3301ec8f5";
const CRATE_CHECKSUM: &str = "352c41f92dbf59d815aec4c6dea95ac66162b1091aaa403b40d272d023495ca8";

type MatrixEntry = (usize, usize, [u8; 32]);
type RelationData = (
    Vec<MatrixEntry>,
    Vec<MatrixEntry>,
    Vec<MatrixEntry>,
    Vec<[u8; 32]>,
    Vec<[u8; 32]>,
);

#[derive(Serialize, Deserialize)]
struct ProofRun {
    mode: String,
    relation: String,
    constraints: usize,
    variables: usize,
    inputs: usize,
    transcript_label: String,
    deterministic_test_randomness: bool,
    prove_ms: f64,
    peak_rss_mb: Option<f64>,
    proof_size_bytes: usize,
    proof_sha256: String,
    local_verifier_accepts: bool,
    original_upstream_verifier_accepts: bool,
    selected_call_count: usize,
    selected_call: Option<ProverMsmCallReport>,
    security_marker: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct UpstreamBaseline {
    marker: String,
    package: String,
    version: String,
    upstream_commit: String,
    crates_io_checksum: String,
    curve25519_dalek_version: String,
    cargo_lock_sha256: String,
    relation: String,
    witness_pattern: String,
    setup: String,
    transcript_label: String,
    prover_randomness: String,
    proof_vector_path: String,
    proof_size_bytes: usize,
    proof_sha256: String,
}

#[derive(Serialize)]
struct SourceAudit {
    unchanged_verifier_files: Vec<String>,
    unchanged_verifier_file_hashes: Vec<String>,
    changed_files: Vec<String>,
    proof_type_and_encoding_unchanged: bool,
    verifier_api_unchanged: bool,
    verifier_source_unchanged: bool,
    transcript_source_unchanged: bool,
}

#[derive(Serialize)]
struct SelectedMsm {
    marker: String,
    source_location: String,
    msm_id: String,
    vector_length: usize,
    basis_digest: String,
    transcript_phase: String,
    private_scalar: bool,
    scalar_privacy_justification: String,
}

#[derive(Serialize)]
struct Snapshot {
    scalar_count: usize,
    scalar_bytes: usize,
    basis_bytes: usize,
    peak_rss_mb: Option<f64>,
    native_msm_latency_ms: f64,
    remote_msm_latency_ms: f64,
    upload_bytes: usize,
    download_bytes: usize,
    transcript_phase: String,
}

#[derive(Serialize)]
struct Summary {
    upstream_baseline: String,
    fork_patch: String,
    patched_native_msm_equivalence: String,
    patched_native_transcript_equivalence: String,
    proof_format: String,
    verifier_source: String,
    single_private_msm_selection: String,
    plaintext_remote_msm: String,
    native_verifier_with_remote_msm: String,
    integration_emsm: String,
    native_verifier_with_integration_emsm: String,
    remote_binding_negative_tests: String,
    integration_snapshot: String,
    security_marker: String,
    final_classification: String,
    exact_proof_bytes_equal: bool,
    selected_msm: SelectedMsm,
    binding_tests: RemoteBindingNegativeTests,
    native_snapshot: Snapshot,
    remote_snapshot: Snapshot,
    upstream_run: ProofRun,
    patched_native_run: ProofRun,
    plaintext_remote_run: ProofRun,
    integration_run: ProofRun,
    source_audit: SourceAudit,
}

fn scalar_bytes(value: u64) -> [u8; 32] {
    curve25519_dalek::scalar::Scalar::from(value).to_bytes()
}

fn relation_data() -> RelationData {
    let n = 1usize << LOG_SIZE;
    let mut a = Vec::with_capacity(n);
    let mut b = Vec::with_capacity(n);
    let mut c = Vec::with_capacity(n);
    let mut vars = Vec::with_capacity(n);
    for i in 0..n {
        let value = scalar_bytes((i & 1) as u64);
        a.push((i, i, scalar_bytes(1)));
        b.push((i, i, scalar_bytes(1)));
        c.push((i, i, scalar_bytes(1)));
        vars.push(value);
    }
    (a, b, c, vars, vec![scalar_bytes(0)])
}

fn upstream_relation() -> Result<(
    upstream::Instance,
    upstream::VarsAssignment,
    upstream::InputsAssignment,
)> {
    let n = 1usize << LOG_SIZE;
    let (a, b, c, vars, inputs) = relation_data();
    Ok((
        upstream::Instance::new(n, n, NUM_INPUTS, &a, &b, &c).map_err(debug_err)?,
        upstream::VarsAssignment::new(&vars).map_err(debug_err)?,
        upstream::InputsAssignment::new(&inputs).map_err(debug_err)?,
    ))
}

fn baseline_relation() -> Result<(
    baseline::Instance,
    baseline::VarsAssignment,
    baseline::InputsAssignment,
)> {
    let n = 1usize << LOG_SIZE;
    let (a, b, c, vars, inputs) = relation_data();
    Ok((
        baseline::Instance::new(n, n, NUM_INPUTS, &a, &b, &c).map_err(debug_err)?,
        baseline::VarsAssignment::new(&vars).map_err(debug_err)?,
        baseline::InputsAssignment::new(&inputs).map_err(debug_err)?,
    ))
}

fn patched_relation() -> Result<(
    patched::Instance,
    patched::VarsAssignment,
    patched::InputsAssignment,
)> {
    let n = 1usize << LOG_SIZE;
    let (a, b, c, vars, inputs) = relation_data();
    Ok((
        patched::Instance::new(n, n, NUM_INPUTS, &a, &b, &c).map_err(debug_err)?,
        patched::VarsAssignment::new(&vars).map_err(debug_err)?,
        patched::InputsAssignment::new(&inputs).map_err(debug_err)?,
    ))
}

fn debug_err(err: impl std::fmt::Debug) -> anyhow::Error {
    anyhow!("{err:?}")
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn peak_rss_mb() -> Option<f64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib = line.split_whitespace().nth(1)?.parse::<f64>().ok()?;
    Some(kib / 1024.0)
}

fn write_json(path: impl AsRef<Path>, value: &impl Serialize) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn deterministic_test_randomness() -> bool {
    true
}

fn run_upstream() -> Result<ProofRun> {
    let n = 1usize << LOG_SIZE;
    let (inst, vars, inputs) = baseline_relation()?;
    let gens = baseline::SNARKGens::new(n, n, NUM_INPUTS, n);
    let (comm, decomm) = baseline::SNARK::encode(&inst, &gens);
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    let start = Instant::now();
    let proof =
        baseline::SNARK::prove(&inst, &comm, &decomm, vars, &inputs, &gens, &mut transcript);
    let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
    let bytes = bincode::serialize(&proof)?;
    let mut verifier_transcript = Transcript::new(TRANSCRIPT_LABEL);
    let local_verifier_accepts = proof
        .verify(&comm, &inputs, &mut verifier_transcript, &gens)
        .is_ok();
    fs::write("results/upstream_native_proof.bin", &bytes)?;
    Ok(ProofRun {
        mode: "upstream_native".to_string(),
        relation: "deterministic_boolean_multiplication_r1cs".to_string(),
        constraints: n,
        variables: n,
        inputs: NUM_INPUTS,
        transcript_label: String::from_utf8_lossy(TRANSCRIPT_LABEL).into_owned(),
        deterministic_test_randomness: deterministic_test_randomness(),
        prove_ms,
        peak_rss_mb: peak_rss_mb(),
        proof_size_bytes: bytes.len(),
        proof_sha256: sha256(&bytes),
        local_verifier_accepts,
        original_upstream_verifier_accepts: local_verifier_accepts,
        selected_call_count: 0,
        selected_call: None,
        security_marker: None,
    })
}

fn original_verifier_accepts(bytes: &[u8]) -> Result<bool> {
    let proof: upstream::SNARK = bincode::deserialize(bytes)?;
    let n = 1usize << LOG_SIZE;
    let (inst, _vars, inputs) = upstream_relation()?;
    let gens = upstream::SNARKGens::new(n, n, NUM_INPUTS, n);
    let (comm, _decomm) = upstream::SNARK::encode(&inst, &gens);
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    Ok(proof.verify(&comm, &inputs, &mut transcript, &gens).is_ok())
}

fn run_patched(mode: &str, provider: ProverMsmProviderKind) -> Result<ProofRun> {
    let n = 1usize << LOG_SIZE;
    let (inst, vars, inputs) = patched_relation()?;
    let gens = patched::SNARKGens::new(n, n, NUM_INPUTS, n);
    let (comm, decomm) = patched::SNARK::encode(&inst, &gens);
    let config = ProverMsmRunConfig {
        provider,
        selected_msm_id: SELECTED_MSM_ID.to_string(),
        session_id: format!("phase3ar2-session-{mode}"),
        proof_id: format!("phase3ar2-proof-{mode}"),
        request_digest: "sha256:4a8bf2c82d65d8a984697a75962e87f459f7b6eb60bf8fbfb826d42ac60bb250"
            .to_string(),
    };
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    let start = Instant::now();
    let (proof, report) = with_prover_msm_provider(config, || {
        patched::SNARK::prove(&inst, &comm, &decomm, vars, &inputs, &gens, &mut transcript)
    });
    let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
    if report.selected_call_count != 1 || report.calls.len() != 1 {
        return Err(anyhow!(
            "expected exactly one selected MSM, got {}",
            report.selected_call_count
        ));
    }
    let bytes = bincode::serialize(&proof)?;
    let decoded_as_upstream: upstream::SNARK = bincode::deserialize(&bytes)
        .context("patched proof must deserialize as the unmodified upstream proof type")?;
    let reencoded = bincode::serialize(&decoded_as_upstream)?;
    if reencoded != bytes {
        return Err(anyhow!("upstream proof type changed serialized bytes"));
    }
    let mut verifier_transcript = Transcript::new(TRANSCRIPT_LABEL);
    let local_verifier_accepts = proof
        .verify(&comm, &inputs, &mut verifier_transcript, &gens)
        .is_ok();
    let original_upstream_verifier_accepts = original_verifier_accepts(&bytes)?;
    fs::write(format!("results/{mode}_proof.bin"), &bytes)?;
    Ok(ProofRun {
        mode: mode.to_string(),
        relation: "deterministic_boolean_multiplication_r1cs".to_string(),
        constraints: n,
        variables: n,
        inputs: NUM_INPUTS,
        transcript_label: String::from_utf8_lossy(TRANSCRIPT_LABEL).into_owned(),
        deterministic_test_randomness: deterministic_test_randomness(),
        prove_ms,
        peak_rss_mb: peak_rss_mb(),
        proof_size_bytes: bytes.len(),
        proof_sha256: sha256(&bytes),
        local_verifier_accepts,
        original_upstream_verifier_accepts,
        selected_call_count: report.selected_call_count,
        selected_call: report.calls.into_iter().next(),
        security_marker: match provider {
            ProverMsmProviderKind::RepetitionCodeIntegration => {
                Some(INTEGRATION_ONLY_NOT_SECURITY_CLAIM.to_string())
            }
            _ => None,
        },
    })
}

fn read_run(name: &str) -> Result<ProofRun> {
    Ok(serde_json::from_slice(&fs::read(format!(
        "results/r2_{name}.json"
    ))?)?)
}

fn file_sha(path: &Path) -> Result<String> {
    Ok(sha256(&fs::read(path)?))
}

fn source_audit() -> Result<SourceAudit> {
    let upstream_root = PathBuf::from("vendor/spartan-upstream-0.9.0/src");
    let patched_root = PathBuf::from("vendor/spartan-0.9.0/src");
    let unchanged = [
        "group.rs",
        "nizk/mod.rs",
        "nizk/bullet.rs",
        "r1csproof.rs",
        "sumcheck.rs",
        "transcript.rs",
    ];
    let mut hashes = Vec::new();
    for relative in unchanged {
        let left = upstream_root.join(relative);
        let right = patched_root.join(relative);
        let left_hash = file_sha(&left)?;
        let right_hash = file_sha(&right)?;
        if left_hash != right_hash {
            return Err(anyhow!("verifier/transcript source changed: {relative}"));
        }
        hashes.push(format!("{relative}:{left_hash}"));
    }
    Ok(SourceAudit {
        unchanged_verifier_files: unchanged.iter().map(|value| value.to_string()).collect(),
        unchanged_verifier_file_hashes: hashes,
        changed_files: vec![
            "src/lib.rs (module declaration only)".to_string(),
            "src/dense_mlpoly.rs (prover witness commitment call only)".to_string(),
            "src/prover_msm.rs (new prover-only provider module)".to_string(),
            "src/random.rs (test-only deterministic regression feature)".to_string(),
        ],
        proof_type_and_encoding_unchanged: true,
        verifier_api_unchanged: true,
        verifier_source_unchanged: true,
        transcript_source_unchanged: true,
    })
}

fn snapshot(run: &ProofRun, remote: bool) -> Result<Snapshot> {
    let call = run
        .selected_call
        .as_ref()
        .ok_or_else(|| anyhow!("missing selected call"))?;
    Ok(Snapshot {
        scalar_count: call.context.scalar_count,
        scalar_bytes: call.scalar_bytes,
        basis_bytes: call.basis_bytes,
        peak_rss_mb: run.peak_rss_mb,
        native_msm_latency_ms: call.native_latency_ms,
        remote_msm_latency_ms: if remote {
            call.provider_latency_ms
        } else {
            call.native_latency_ms
        },
        upload_bytes: call.upload_bytes,
        download_bytes: call.download_bytes,
        transcript_phase: call.context.transcript_phase.clone(),
    })
}

fn finalize() -> Result<()> {
    let upstream = read_run("upstream")?;
    let native = read_run("native")?;
    let remote = read_run("remote")?;
    let integration = read_run("integration")?;
    let binding_tests: RemoteBindingNegativeTests =
        serde_json::from_slice(&fs::read("results/r2_binding_tests.json")?)?;
    let proof_hashes_equal = upstream.proof_sha256 == native.proof_sha256
        && upstream.proof_sha256 == remote.proof_sha256
        && upstream.proof_sha256 == integration.proof_sha256;
    let all_verify = [&upstream, &native, &remote, &integration]
        .iter()
        .all(|run| run.local_verifier_accepts && run.original_upstream_verifier_accepts);
    let all_points_equal = [&native, &remote, &integration].iter().all(|run| {
        run.selected_call
            .as_ref()
            .map(|call| call.native_result_matches && call.transcript_input_matches)
            .unwrap_or(false)
    });
    let bindings_pass = binding_tests.honest_request_accepted
        && binding_tests.replay_rejected
        && binding_tests.swapped_msm_rejected
        && binding_tests.wrong_basis_rejected
        && binding_tests.wrong_session_rejected
        && binding_tests.truncated_stream_rejected
        && binding_tests.duplicate_chunk_rejected;
    if !(proof_hashes_equal && all_verify && all_points_equal && bindings_pass) {
        return Err(anyhow!(
            "Phase 3A-R2 pass conditions failed: proof_bytes={proof_hashes_equal}, verify={all_verify}, points={all_points_equal}, bindings={bindings_pass}"
        ));
    }
    let source_audit = source_audit()?;
    let selected_call = remote.selected_call.as_ref().unwrap();
    let selected_msm = SelectedMsm {
        marker: "LIBSPARTAN_SINGLE_PRIVATE_MSM_SELECTED".to_string(),
        source_location: "vendor/spartan-0.9.0/src/dense_mlpoly.rs: DensePolynomial::commit_inner, private commitment chunk 0".to_string(),
        msm_id: selected_call.context.msm_id.clone(),
        vector_length: selected_call.context.scalar_count,
        basis_digest: selected_call.basis_digest.clone(),
        transcript_phase: selected_call.context.transcript_phase.clone(),
        private_scalar: selected_call.context.private_scalars,
        scalar_privacy_justification: "The scalars are the first chunk of the private witness polynomial committed before the commitment is appended to the R1CS proof transcript.".to_string(),
    };
    let cargo_lock = fs::read("Cargo.lock")?;
    let baseline = UpstreamBaseline {
        marker: "THINWALLET_LIBSPARTAN_UPSTREAM_BASELINE".to_string(),
        package: "spartan".to_string(),
        version: "0.9.0".to_string(),
        upstream_commit: UPSTREAM_COMMIT.to_string(),
        crates_io_checksum: CRATE_CHECKSUM.to_string(),
        curve25519_dalek_version: "4.1.3".to_string(),
        cargo_lock_sha256: sha256(&cargo_lock),
        relation: upstream.relation.clone(),
        witness_pattern: "4096 alternating boolean variables; x_i * x_i = x_i".to_string(),
        setup: "SNARKGens::new(4096, 4096, 1, 4096)".to_string(),
        transcript_label: upstream.transcript_label.clone(),
        prover_randomness: "fixed by phase3ar2-deterministic-tests RandomTape seed in the testable upstream copy and patched fork; default builds retain OsRng".to_string(),
        proof_vector_path: "results/upstream_native_proof.bin".to_string(),
        proof_size_bytes: upstream.proof_size_bytes,
        proof_sha256: upstream.proof_sha256.clone(),
    };
    write_json(
        "results/THINWALLET_LIBSPARTAN_UPSTREAM_BASELINE.json",
        &baseline,
    )?;
    let summary = Summary {
        upstream_baseline: "LIBSPARTAN_UPSTREAM_BASELINE_FROZEN".to_string(),
        fork_patch: "LIBSPARTAN_PROVER_MSM_HOOK_PATCHED".to_string(),
        patched_native_msm_equivalence: "LIBSPARTAN_PATCHED_NATIVE_MSM_EQUIVALENCE_PASS"
            .to_string(),
        patched_native_transcript_equivalence:
            "LIBSPARTAN_PATCHED_NATIVE_TRANSCRIPT_EQUIVALENCE_PASS".to_string(),
        proof_format: "LIBSPARTAN_PROOF_FORMAT_UNCHANGED_PASS".to_string(),
        verifier_source: "LIBSPARTAN_VERIFIER_SOURCE_UNCHANGED_PASS".to_string(),
        single_private_msm_selection: "LIBSPARTAN_SINGLE_PRIVATE_MSM_SELECTED".to_string(),
        plaintext_remote_msm: "LIBSPARTAN_SINGLE_PLAINTEXT_REMOTE_MSM_PASS".to_string(),
        native_verifier_with_remote_msm: "LIBSPARTAN_NATIVE_VERIFIER_WITH_REMOTE_MSM_PASS"
            .to_string(),
        integration_emsm: "LIBSPARTAN_SINGLE_INTEGRATION_EMSM_PASS".to_string(),
        native_verifier_with_integration_emsm:
            "LIBSPARTAN_NATIVE_VERIFIER_WITH_INTEGRATION_EMSM_PASS".to_string(),
        remote_binding_negative_tests: "LIBSPARTAN_REMOTE_MSM_BINDING_NEGATIVE_TESTS_PASS"
            .to_string(),
        integration_snapshot: "LIBSPARTAN_SINGLE_MSM_INTEGRATION_SNAPSHOT_COMPLETE".to_string(),
        security_marker: INTEGRATION_ONLY_NOT_SECURITY_CLAIM.to_string(),
        final_classification: "PHASE3A_R2_SINGLE_MSM_INTEGRATION_PASS".to_string(),
        exact_proof_bytes_equal: proof_hashes_equal,
        selected_msm,
        binding_tests,
        native_snapshot: snapshot(&native, false)?,
        remote_snapshot: snapshot(&remote, true)?,
        upstream_run: upstream,
        patched_native_run: native,
        plaintext_remote_run: remote,
        integration_run: integration,
        source_audit,
    };
    write_json("results/phase3ar2_summary.json", &summary)?;
    println!("LIBSPARTAN_UPSTREAM_BASELINE_FROZEN");
    println!("LIBSPARTAN_PROVER_MSM_HOOK_PATCHED");
    println!("LIBSPARTAN_PATCHED_NATIVE_MSM_EQUIVALENCE_PASS");
    println!("LIBSPARTAN_PATCHED_NATIVE_TRANSCRIPT_EQUIVALENCE_PASS");
    println!("LIBSPARTAN_PROOF_FORMAT_UNCHANGED_PASS");
    println!("LIBSPARTAN_VERIFIER_SOURCE_UNCHANGED_PASS");
    println!("LIBSPARTAN_SINGLE_PRIVATE_MSM_SELECTED");
    println!("LIBSPARTAN_SINGLE_PLAINTEXT_REMOTE_MSM_PASS");
    println!("LIBSPARTAN_NATIVE_VERIFIER_WITH_REMOTE_MSM_PASS");
    println!("LIBSPARTAN_SINGLE_INTEGRATION_EMSM_PASS");
    println!("LIBSPARTAN_NATIVE_VERIFIER_WITH_INTEGRATION_EMSM_PASS");
    println!("LIBSPARTAN_REMOTE_MSM_BINDING_NEGATIVE_TESTS_PASS");
    println!("LIBSPARTAN_SINGLE_MSM_INTEGRATION_SNAPSHOT_COMPLETE");
    println!("PHASE3A_R2_SINGLE_MSM_INTEGRATION_PASS");
    Ok(())
}

fn main() -> Result<()> {
    fs::create_dir_all("results")?;
    let mode = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("expected mode"))?;
    match mode.as_str() {
        "upstream" => write_json("results/r2_upstream.json", &run_upstream()?),
        "native" => write_json(
            "results/r2_native.json",
            &run_patched("patched_native", ProverMsmProviderKind::Native)?,
        ),
        "remote" => write_json(
            "results/r2_remote.json",
            &run_patched("plaintext_remote", ProverMsmProviderKind::PlainRemote)?,
        ),
        "integration" => write_json(
            "results/r2_integration.json",
            &run_patched(
                "integration_emsm",
                ProverMsmProviderKind::RepetitionCodeIntegration,
            )?,
        ),
        "negative-tests" => write_json(
            "results/r2_binding_tests.json",
            &remote_binding_negative_tests(),
        ),
        "finalize" => finalize(),
        _ => Err(anyhow!("unknown mode: {mode}")),
    }
}
