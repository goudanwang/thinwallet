use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use libspartan_baseline as baseline;
use libspartan_patched as patched;
use merlin::Transcript;
use patched::pbmo_commitment::{with_full_pbmo_provider, FullPbmoRunConfig, FullPbmoRunReport};
use preprocessed_pbmo::{
    basis_digest, context_binding_digest, detect_duplicate_ids, reset_token_durability_metrics,
    token_durability_metrics, LoopbackTransport, NativeLocalPbmoProvider, PbmoContext,
    PlainRemotePbmoProvider, PreprocessedMaliciousPbmoProvider, PreprocessedPbmoProvider,
    PreprocessedSemihonestPbmoProvider, RelationShape, ReservationBinding,
    SoftwareCrashConsistentProvider, SoftwareTokenStoreKeyProvider, TcpTransport, Token,
    TokenBinding, TokenState, TokenStore, BACKEND_REVISION, PROTOCOL_VERSION,
};
use rand::rngs::{OsRng, StdRng};
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::collections::BTreeMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use patched::memory_trace::{self, AllocationClass};

#[path = "../credential_source/mod.rs"]
mod credential_source;
#[path = "../credential_workloads.rs"]
mod credential_workloads;

// The tracing allocator enters TLS during allocation and faults before main on
// Android/Bionic. Device runs use the system allocator and external /proc PSS/RSS tracing.
#[cfg(not(target_os = "android"))]
#[global_allocator]
static V3A_ALLOCATOR: patched::memory_trace::TrackingAllocator =
    patched::memory_trace::TrackingAllocator;

static PROCESS_TIMER: OnceLock<Instant> = OnceLock::new();

const RELATION_STATE: AllocationClass = AllocationClass {
    source_file: "src/bin/phase_v2_pbmo.rs",
    function: "relation_entries",
    component: "R1CS instance",
    element_type: "MatrixEntry/[u8;32]",
    privacy: "mixed",
    replayable: true,
    streamable: true,
};
const INSTANCE_STATE: AllocationClass = AllocationClass {
    source_file: "src/bin/phase_v2_pbmo.rs",
    function: "Instance::new",
    component: "R1CS instance",
    element_type: "SparseMatEntry",
    privacy: "public",
    replayable: true,
    streamable: true,
};
const ASSIGNMENT_STATE: AllocationClass = AllocationClass {
    source_file: "src/bin/phase_v2_pbmo.rs",
    function: "VarsAssignment::new",
    component: "witness assignment",
    element_type: "Scalar",
    privacy: "private",
    replayable: true,
    streamable: true,
};
const GENERATOR_STATE: AllocationClass = AllocationClass {
    source_file: "src/bin/phase_v2_pbmo.rs",
    function: "SNARKGens::new",
    component: "commitment bases",
    element_type: "RistrettoPoint",
    privacy: "public",
    replayable: true,
    streamable: false,
};
const ENCODE_STATE: AllocationClass = AllocationClass {
    source_file: "src/bin/phase_v2_pbmo.rs",
    function: "SNARK::encode",
    component: "sparse polynomial structures",
    element_type: "mixed public encoding state",
    privacy: "public",
    replayable: true,
    streamable: true,
};
const PBMO_STATE: AllocationClass = AllocationClass {
    source_file: "src/bin/phase_v2_pbmo.rs",
    function: "patched_run:PBMO_setup",
    component: "PBMO token",
    element_type: "Scalar/RistrettoPoint",
    privacy: "private/masked",
    replayable: false,
    streamable: true,
};
const PROVE_STATE: AllocationClass = AllocationClass {
    source_file: "src/bin/phase_v2_pbmo.rs",
    function: "SNARK::prove",
    component: "proof transcript",
    element_type: "mixed prover state",
    privacy: "mixed",
    replayable: false,
    streamable: false,
};
const VERIFY_STATE: AllocationClass = AllocationClass {
    source_file: "src/bin/phase_v2_pbmo.rs",
    function: "SNARK::verify",
    component: "proof serialization",
    element_type: "verifier state",
    privacy: "public",
    replayable: true,
    streamable: false,
};

const TRANSCRIPT_LABEL: &[u8] = b"thinwallet_phase_v2_pbmo_fixed";
const PHASE5B_ARTIFACT_VERSION: &str = "phase5b-pregenerated-token";
const PHASE5B_MANIFEST_SCHEMA: &str = "thinwallet-phase5b-token-store-v1";
const PHASE5B_MANIFEST_NAME: &str = "phase5b_manifest.json";
type MatrixEntry = (usize, usize, [u8; 32]);
type RelationEntries = (
    Vec<MatrixEntry>,
    Vec<MatrixEntry>,
    Vec<MatrixEntry>,
    Vec<[u8; 32]>,
    Vec<[u8; 32]>,
);

struct ActiveTokenReservation {
    store: TokenStore,
    token_id: [u8; 16],
    binding: ReservationBinding,
    generation: u64,
    rng: StdRng,
    armed: bool,
}

impl ActiveTokenReservation {
    fn new(store: TokenStore, token: &Token, rng: StdRng) -> Result<Self> {
        Ok(Self {
            store,
            token_id: token.token_id,
            binding: token
                .reservation_binding()
                .cloned()
                .ok_or_else(|| anyhow!("reserved token is missing lifecycle binding"))?,
            generation: token.record_generation(),
            rng,
            armed: true,
        })
    }

    fn mark_spent(&mut self) -> Result<TokenState> {
        let state = self
            .store
            .mark_spent(
                &self.token_id,
                &self.binding,
                self.generation,
                &mut self.rng,
            )
            .map_err(|error| anyhow!(error.to_string()))?;
        self.armed = false;
        Ok(state)
    }
}

impl Drop for ActiveTokenReservation {
    fn drop(&mut self) {
        if self.armed {
            match self.store.mark_burned(
                &self.token_id,
                &self.binding,
                self.generation,
                &mut self.rng,
            ) {
                Ok(TokenState::Burned) => {
                    self.armed = false;
                }
                Ok(state) => {
                    eprintln!("TOKEN_FAIL_CLOSED unexpected burn state: {state:?}");
                }
                Err(error) => {
                    eprintln!("TOKEN_FAIL_CLOSED durable burn failed; RESERVED recovery required: {error}");
                }
            }
        }
    }
}

// The Android runner supplies an app-private root. The canonical store and
// journal formats remain exactly the V3B/PBMO implementations.
#[allow(dead_code)]
type AndroidFileBackedStateStore = patched::multi_state_store::MultiObjectFileBackedStateStore;
#[allow(dead_code)]
type AndroidTokenJournalStore = TokenStore;

#[derive(Serialize)]
struct RunResult {
    mode: String,
    log_size: usize,
    relation_size: usize,
    q: usize,
    m: usize,
    prove_ms: f64,
    peak_rss_mb: Option<f64>,
    proof_size_bytes: usize,
    token_size_bytes: Option<usize>,
    proof_sha256: String,
    spartan_randomness_mode: Option<String>,
    r1cs_sat_proof_sha256: Option<String>,
    r1cs_eval_proof_sha256: Option<String>,
    proof_deserialization_pass: bool,
    patched_verifier_accepts: bool,
    original_upstream_verifier_accepts: Option<bool>,
    full_commitment_report: Option<FullPbmoRunReport>,
    native_blinding_preserved_locally: bool,
    verifier_source_modified: bool,
    durable_token_state: Option<String>,
    token_path_classification: Option<String>,
    token_selected_id_sha256: Option<String>,
    online_generation_assertions_passed: Option<bool>,
    token_durable_sync_calls: Option<u64>,
    token_durable_sync_ms: Option<f64>,
    execution_counters: BTreeMap<String, u64>,
    audit_digests: serde_json::Value,
    measurement_scope: thinwallet_instrumentation::MeasurementScopeReport,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Phase5bTokenRecord {
    token_id_hex: String,
    token_id_sha256: String,
    token_state: String,
    token_bytes: Option<u64>,
    token_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Phase5bManifestPayload {
    schema_version: String,
    artifact_version: String,
    protocol_version: u16,
    curve_backend_identifier: String,
    workload_identifier: String,
    q: u32,
    m: u32,
    basis_hash: String,
    public_invocation_descriptor: String,
    context_domain_separation: String,
    server_protocol_binding: String,
    creation_build_hash: String,
    publication_state: String,
    tokens: Vec<Phase5bTokenRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Phase5bManifest {
    payload: Phase5bManifestPayload,
    integrity_algorithm: String,
    integrity_tag_hex: String,
}

fn scalar_bytes(value: u64) -> [u8; 32] {
    curve25519_dalek::scalar::Scalar::from(value).to_bytes()
}

fn relation_entries(log_size: usize) -> RelationEntries {
    let _memory_scope = memory_trace::scope(&RELATION_STATE);
    let n = 1usize << log_size;
    if let Ok(path) = std::env::var("THINWALLET_CREDENTIAL_SOURCE_PATH") {
        let workload_name = std::env::var("THINWALLET_CREDENTIAL_WORKLOAD")
            .expect("authenticated credential replay requires a workload");
        let workload = credential_workloads::profile_s::ProfileSWorkload::parse(&workload_name)
            .expect("authenticated credential replay requires Profile S WK");
        let fixture = authenticated_replay_fixture(Path::new(&path), workload, n)
            .unwrap_or_else(|error| panic!("authenticated credential replay failed: {error}"));
        return (
            fixture.a,
            fixture.b,
            fixture.c,
            fixture.vars,
            fixture.inputs,
        );
    }
    if let Ok(name) = std::env::var("THINWALLET_CREDENTIAL_WORKLOAD") {
        let fixture = if let Some(workload) =
            credential_workloads::profile_s::ProfileSWorkload::parse(&name)
        {
            credential_workloads::profile_s::build_profile_s(
                workload,
                credential_workloads::profile_s::ProfileSMutation::Valid,
                n,
            )
            .unwrap_or_else(|error| panic!("Profile S relation build failed: {error}"))
        } else {
            let workload = credential_workloads::Workload::parse(&name)
                .unwrap_or_else(|| panic!("unknown credential workload {name}"));
            credential_workloads::build(workload, credential_workloads::Mutation::Valid, n)
                .unwrap_or_else(|error| panic!("credential relation build failed: {error}"))
        };
        return (
            fixture.a,
            fixture.b,
            fixture.c,
            fixture.vars,
            fixture.inputs,
        );
    }
    let mut a = Vec::with_capacity(n);
    let mut b = Vec::with_capacity(n);
    let mut c = Vec::with_capacity(n);
    let mut vars = Vec::with_capacity(n);
    for i in 0..n {
        let one = scalar_bytes(1);
        a.push((i, i, one));
        b.push((i, i, one));
        c.push((i, i, one));
        vars.push(scalar_bytes((i & 1) as u64));
    }
    (a, b, c, vars, vec![scalar_bytes(0)])
}

fn authenticated_replay_fixture(
    path: &Path,
    workload: credential_workloads::profile_s::ProfileSWorkload,
    padded_size: usize,
) -> Result<credential_workloads::RelationFixture> {
    use credential_workloads::profile_s::{ProfileSReplayRecord, ProfileSWorkload};
    let source_open_start = Instant::now();
    let provider = credential_source::SoftwareCredentialSourceKeyProvider::new(
        "thinwallet-v4e-software-key-1",
        [0x5au8; 32],
    );
    let reader = credential_source::CredentialSourceReader::open_authenticated(path, &provider)
        .map_err(|error| anyhow!(error.to_string()))?;
    eprintln!(
        "V4F_PHASE_LATENCY phase=credential_source_open_and_authentication elapsed_ms={:.6}",
        source_open_start.elapsed().as_secs_f64() * 1000.0
    );
    let header = reader.header();
    let ProfileSWorkload::WK {
        credentials,
        revocation_count,
        revocation_depth,
        revocation_backend,
    } = workload
    else {
        return Err(anyhow!("authenticated replay supports WK only"));
    };
    if header.credential_count != credentials as u32
        || header.revocation_count != revocation_count as u32
        || header.revocation_depth != revocation_depth as u32
        || header.revocation_backend != revocation_backend.label()
        || header.revocation_set != (0..revocation_count as u32).collect::<Vec<_>>()
        || header.backend_revision != "libspartan-0.9.0-thinwallet-fs7"
    {
        return Err(anyhow!("authenticated source workload/backend mismatch"));
    }
    let expected_session = std::env::var("THINWALLET_PROOF_SESSION_ID")
        .map_err(|_| anyhow!("THINWALLET_PROOF_SESSION_ID is required"))?;
    if expected_session != hex(&header.proof_session_id) {
        return Err(anyhow!("authenticated source proof-session mismatch"));
    }
    let expected_root = if revocation_count == 0 {
        [0; 32]
    } else {
        credential_workloads::profile_s::fixture_revocation_material(
            revocation_count,
            0,
            revocation_depth,
        )
        .1
    };
    if header.registry_root != expected_root || header.registry_epoch != 73 {
        return Err(anyhow!("authenticated source registry mismatch"));
    }

    let mut replay = Vec::with_capacity(credentials);
    let replay_start = Instant::now();
    reader
        .for_each_record(|record| {
            let value = |bytes: &[u8; 32]| {
                if bytes[8..].iter().any(|byte| *byte != 0) {
                    return Err(credential_source::CredentialSourceError::Format(
                        "fixture integer exceeds u64".into(),
                    ));
                }
                let mut lower = [0u8; 8];
                lower.copy_from_slice(&bytes[..8]);
                Ok(u64::from_le_bytes(lower))
            };
            if record.hidden_attributes.len() != 4
                || record.signed_credential_commitment.len() != 32
            {
                return Err(credential_source::CredentialSourceError::Format(
                    "Profile S replay field count mismatch".into(),
                ));
            }
            let mut expected_commitment = [0u8; 32];
            expected_commitment.copy_from_slice(&record.signed_credential_commitment);
            replay.push(ProfileSReplayRecord {
                credential_type: record.credential_type,
                issuer_id: record.issuer_id,
                credential_id: value(&record.hidden_attributes[0])?,
                holder_secret: value(&record.holder_binding)?,
                schema_id: value(&record.hidden_attributes[1])?,
                age: value(&record.hidden_attributes[2])?,
                country: value(&record.hidden_attributes[3])?,
                expiry: record.expiry,
                revocation_id: record.revocation_identifier,
                issuance_epoch: record.issuance_epoch,
                salt: record.commitment_salt,
                issuer_key_digest: record.issuer_public_key_digest,
                expected_commitment,
                revocation_path: record.revocation_witness.clone(),
            });
            Ok(())
        })
        .map_err(|error| anyhow!(error.to_string()))?;
    eprintln!(
        "V4F_PHASE_LATENCY phase=compact_source_replay elapsed_ms={:.6}",
        replay_start.elapsed().as_secs_f64() * 1000.0
    );
    let relation_start = Instant::now();
    let fixture = credential_workloads::profile_s::build_profile_s_from_records(
        workload,
        padded_size,
        &replay,
    )
    .map_err(|error| anyhow!(error))?;
    eprintln!(
        "V4F_PHASE_LATENCY phase=relation_construction elapsed_ms={:.6}",
        relation_start.elapsed().as_secs_f64() * 1000.0
    );
    eprintln!(
        "V4F_PHASE_LATENCY phase=witness_generation elapsed_ms={:.6}",
        fixture.metadata.witness_generation_ms
    );
    let relation_digest = credential_relation_digest(&fixture);
    let public_input_digest = credential_source::digest_bytes(
        b"thinwallet/public-inputs/v1",
        &fixture
            .inputs
            .iter()
            .map(|value| value.as_slice())
            .collect::<Vec<_>>(),
    );
    if relation_digest != header.relation_layout_digest
        || public_input_digest != header.public_input_digest
    {
        return Err(anyhow!(
            "authenticated source relation/public-input mismatch"
        ));
    }
    Ok(fixture)
}

fn credential_relation_digest(fixture: &credential_workloads::RelationFixture) -> [u8; 32] {
    let mut digest = Sha256::new();
    Digest::update(&mut digest, b"thinwallet/relation-layout/v1");
    for matrix in [&fixture.a, &fixture.b, &fixture.c] {
        Digest::update(&mut digest, (matrix.len() as u64).to_be_bytes());
        for (row, column, value) in matrix {
            Digest::update(&mut digest, (*row as u64).to_be_bytes());
            Digest::update(&mut digest, (*column as u64).to_be_bytes());
            Digest::update(&mut digest, value);
        }
    }
    for vector in [&fixture.vars, &fixture.inputs] {
        Digest::update(&mut digest, (vector.len() as u64).to_be_bytes());
        for value in vector {
            Digest::update(&mut digest, value);
        }
    }
    digest.finalize().into()
}

fn relation_id(log_size: usize) -> String {
    match std::env::var("THINWALLET_CREDENTIAL_WORKLOAD") {
        Ok(workload) => {
            let canonical = credential_workloads::profile_s::ProfileSWorkload::parse(&workload)
                .map(|value| value.name())
                .unwrap_or(workload);
            format!("thinwallet-credential-{canonical}-2^{log_size}")
        }
        Err(_) => format!("boolean-multiplication-2^{log_size}"),
    }
}

fn peak_rss_mb() -> Option<f64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    Some(line.split_whitespace().nth(1)?.parse::<f64>().ok()? / 1024.0)
}

fn current_rss_mb() -> Option<f64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    Some(line.split_whitespace().nth(1)?.parse::<f64>().ok()? / 1024.0)
}

#[cfg(target_os = "linux")]
fn release_allocator_pages() {
    unsafe extern "C" {
        fn malloc_trim(pad: usize) -> i32;
    }
    unsafe {
        malloc_trim(0);
    }
}

#[cfg(not(target_os = "linux"))]
fn release_allocator_pages() {}

fn memory_stage(stage: &str) {
    let elapsed_ms = PROCESS_TIMER
        .get_or_init(Instant::now)
        .elapsed()
        .as_secs_f64()
        * 1000.0;
    eprintln!(
        "V3A_MEMORY_STAGE stage={stage} elapsed_ms={elapsed_ms:.6} rss_mb={:?} hwm_mb={:?}",
        current_rss_mb(),
        peak_rss_mb()
    );
    patched::memory_trace::snapshot(stage);
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn phase5b_manifest_tag(payload: &Phase5bManifestPayload) -> Result<String> {
    let encoded = bincode::serialize(payload)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x42; 32])
        .map_err(|error| anyhow!("manifest HMAC key: {error}"))?;
    Mac::update(&mut mac, b"thinwallet/phase5b/token-store-manifest/v1");
    Mac::update(&mut mac, &encoded);
    Ok(hex(&mac.finalize().into_bytes()))
}

fn write_phase5b_manifest(root: &Path, payload: Phase5bManifestPayload) -> Result<()> {
    let manifest = Phase5bManifest {
        integrity_tag_hex: phase5b_manifest_tag(&payload)?,
        integrity_algorithm: "HMAC-SHA256/software-test-key-v1".into(),
        payload,
    };
    fs::create_dir_all(root)?;
    let path = root.join(PHASE5B_MANIFEST_NAME);
    let temporary = root.join(format!("{PHASE5B_MANIFEST_NAME}.tmp"));
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    let mut file = fs::File::create(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    fs::File::open(root)?.sync_all()?;
    Ok(())
}

fn read_phase5b_manifest(root: &Path) -> Result<Phase5bManifest> {
    let path = root.join(PHASE5B_MANIFEST_NAME);
    let manifest: Phase5bManifest = serde_json::from_slice(
        &fs::read(&path)
            .map_err(|error| anyhow!("missing token manifest {}: {error}", path.display()))?,
    )?;
    let expected = phase5b_manifest_tag(&manifest.payload)?;
    if manifest.integrity_algorithm != "HMAC-SHA256/software-test-key-v1"
        || manifest.integrity_tag_hex != expected
    {
        return Err(anyhow!("token manifest integrity validation failed"));
    }
    Ok(manifest)
}

fn parse_hex_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 {
        return Err(anyhow!("expected {} hexadecimal characters", N * 2));
    }
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| anyhow!("invalid hexadecimal value"))?;
    }
    Ok(output)
}

fn phase5b_token_path(root: &Path, token_id: &[u8; 16]) -> PathBuf {
    root.join("tokens").join(format!("{}.pbmo", hex(token_id)))
}

#[cfg(unix)]
fn local_process_cpu_ns() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut value) } != 0 {
        return 0;
    }
    (value.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(value.tv_nsec as u64)
}

#[cfg(not(unix))]
fn local_process_cpu_ns() -> u64 {
    0
}

fn begin_prover_measurement_scope() -> Result<thinwallet_instrumentation::MeasurementScopeGuard> {
    let name = std::env::var("THINWALLET_MEASUREMENT_SCOPE")
        .unwrap_or_else(|_| "prover-deferred-verifier".to_string());
    if std::env::var("THINWALLET_REQUIRE_MOBILE_PROVER_SCOPE").as_deref() == Ok("1")
        && name != "mobile-prover-deferred-verifier"
    {
        return Err(anyhow!("invalid required mobile prover measurement scope"));
    }
    let sample_ms = std::env::var("THINWALLET_METRICS_SAMPLE_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100);
    thinwallet_instrumentation::begin_measurement_scope(&name, sample_ms)
        .map_err(|error| anyhow!(error))
}

fn libspartan_private_basis(m: usize) -> Vec<curve25519_dalek::ristretto::RistrettoPoint> {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
    let mut shake = Shake256::default();
    shake.update(b"gens_r1cs_sat");
    shake.update(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    let mut reader = shake.finalize_xof();
    (0..m)
        .map(|_| {
            let mut uniform = [0u8; 64];
            reader.read(&mut uniform);
            curve25519_dalek::ristretto::RistrettoPoint::from_uniform_bytes(&uniform)
        })
        .collect()
}

fn upstream(log_size: usize) -> Result<RunResult> {
    let measurement_scope_guard = begin_prover_measurement_scope()?;
    let n = 1usize << log_size;
    memory_stage("upstream.before_relation_entries");
    let relation_phase = thinwallet_instrumentation::PhaseGuard::begin("relation_setup");
    let (a, b, c, vars, inputs) = relation_entries(log_size);
    let num_inputs = inputs.len();
    let num_nz_entries = a.len().max(b.len()).max(c.len());
    memory_stage("upstream.after_relation_entries");
    let inst = {
        let _memory_scope = memory_trace::scope(&INSTANCE_STATE);
        baseline::Instance::new(n, n, num_inputs, &a, &b, &c).map_err(debug_err)?
    };
    drop(relation_phase);
    memory_stage("upstream.after_instance");
    let witness_phase = thinwallet_instrumentation::PhaseGuard::begin("witness_construction");
    let vars = {
        let _memory_scope = memory_trace::scope(&ASSIGNMENT_STATE);
        baseline::VarsAssignment::new(&vars).map_err(debug_err)?
    };
    let inputs = baseline::InputsAssignment::new(&inputs).map_err(debug_err)?;
    drop(witness_phase);
    memory_stage("upstream.after_assignments");
    let initialization_phase =
        thinwallet_instrumentation::PhaseGuard::begin("prover_initialization");
    let gens = {
        let _memory_scope = memory_trace::scope(&GENERATOR_STATE);
        baseline::SNARKGens::new(n, n, num_inputs, num_nz_entries)
    };
    memory_stage("upstream.after_gens");
    let (comm, decomm) = {
        let _memory_scope = memory_trace::scope(&ENCODE_STATE);
        baseline::SNARK::encode(&inst, &gens)
    };
    drop(initialization_phase);
    memory_stage("upstream.after_encode");
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    let start = Instant::now();
    let proof = {
        let _memory_scope = memory_trace::scope(&PROVE_STATE);
        let _audit = thinwallet_instrumentation::begin_prover_audit();
        baseline::SNARK::prove(&inst, &comm, &decomm, vars, &inputs, &gens, &mut transcript)
    };
    memory_stage("upstream.after_prove");
    let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
    let serialization_phase = thinwallet_instrumentation::PhaseGuard::begin("proof_serialization");
    let bytes = bincode::serialize(&proof)?;
    if let Some(path) = std::env::var_os("THINWALLET_PROOF_OUT") {
        fs::write(path, &bytes)?;
    }
    drop(serialization_phase);
    let measurement_scope = measurement_scope_guard.finish();
    if !measurement_scope.valid_measurement_scope {
        return Err(anyhow!("invalid_measurement_scope"));
    }
    let mut verifier_transcript = Transcript::new(TRANSCRIPT_LABEL);
    let verification_phase = thinwallet_instrumentation::PhaseGuard::begin("verification");
    let accepts = {
        let _memory_scope = memory_trace::scope(&VERIFY_STATE);
        proof
            .verify(&comm, &inputs, &mut verifier_transcript, &gens)
            .is_ok()
    };
    drop(verification_phase);
    memory_stage("upstream.after_verify");
    let q = 1usize << (log_size / 2);
    let m = 1usize << (log_size - log_size / 2);
    Ok(RunResult {
        mode: "upstream".into(),
        log_size,
        relation_size: n,
        q,
        m,
        prove_ms,
        peak_rss_mb: peak_rss_mb(),
        proof_size_bytes: bytes.len(),
        token_size_bytes: None,
        proof_sha256: sha256(&bytes),
        spartan_randomness_mode: Some("legacy-upstream-shared".into()),
        r1cs_sat_proof_sha256: None,
        r1cs_eval_proof_sha256: None,
        proof_deserialization_pass: bincode::deserialize::<baseline::SNARK>(&bytes).is_ok(),
        patched_verifier_accepts: accepts,
        original_upstream_verifier_accepts: Some(accepts),
        full_commitment_report: None,
        native_blinding_preserved_locally: true,
        verifier_source_modified: false,
        durable_token_state: None,
        token_path_classification: None,
        token_selected_id_sha256: None,
        online_generation_assertions_passed: None,
        token_durable_sync_calls: None,
        token_durable_sync_ms: None,
        execution_counters: thinwallet_instrumentation::counters_snapshot(),
        audit_digests: thinwallet_instrumentation::audit_digests(),
        measurement_scope,
    })
}

fn provider_for(
    mode: &str,
    bases: Vec<curve25519_dalek::ristretto::RistrettoPoint>,
    token: Option<Token>,
) -> Result<Box<dyn PreprocessedPbmoProvider>> {
    let transport = std::env::var("THINWALLET_PBMO_TRANSPORT").unwrap_or_else(|_| "local".into());
    let make_transport = |bases: &[curve25519_dalek::ristretto::RistrettoPoint]| -> Result<Box<dyn preprocessed_pbmo::PbmoTransport>> {
        match transport.as_str() {
            "loopback" => Ok(Box::new(LoopbackTransport::new(bases.to_vec()))),
            "tcp" => {
                let endpoint = std::env::var("THINWALLET_PBMO_ENDPOINT")
                    .map_err(|_| anyhow!("THINWALLET_PBMO_ENDPOINT is required for TCP"))?
                    .parse()?;
                let key_path = std::env::var("THINWALLET_PBMO_PSK_FILE")
                    .map_err(|_| anyhow!("THINWALLET_PBMO_PSK_FILE is required for TCP"))?;
                let bytes = fs::read(key_path)?;
                let key: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("PBMO PSK must be exactly 32 bytes"))?;
                let timeout_ms = std::env::var("THINWALLET_PBMO_TIMEOUT_MS")
                    .ok().and_then(|value| value.parse().ok()).unwrap_or(120_000);
                Ok(Box::new(TcpTransport::new(
                    endpoint,
                    key,
                    Duration::from_millis(10_000),
                    Duration::from_millis(timeout_ms),
                )))
            }
            "local" => Err(anyhow!("local transport has no transport object")),
            other => Err(anyhow!("unknown PBMO transport {other}")),
        }
    };
    Ok(match mode {
        "native" => Box::new(NativeLocalPbmoProvider::new(bases)),
        "plain" => Box::new(PlainRemotePbmoProvider::new(bases)),
        "semi" if transport != "local" => {
            let remote = make_transport(&bases)?;
            Box::new(PreprocessedSemihonestPbmoProvider::new_with_transport(
                bases,
                token.ok_or_else(|| anyhow!("semi-honest PBMO requires a token"))?,
                remote,
            ))
        }
        "malicious" if transport != "local" => {
            let remote = make_transport(&bases)?;
            Box::new(PreprocessedMaliciousPbmoProvider::new_with_transport(
                bases,
                token.ok_or_else(|| anyhow!("malicious PBMO requires a token"))?,
                remote,
            ))
        }
        "semi" => Box::new(PreprocessedSemihonestPbmoProvider::new(
            bases,
            token.ok_or_else(|| anyhow!("semi-honest PBMO requires a token"))?,
        )),
        "malicious" => Box::new(PreprocessedMaliciousPbmoProvider::new(
            bases,
            token.ok_or_else(|| anyhow!("malicious PBMO requires a token"))?,
        )),
        _ => return Err(anyhow!("unknown provider mode {mode}")),
    })
}

fn phase_marker(name: &str) -> Result<()> {
    let Some(path) = std::env::var_os("THINWALLET_PHASE_MARKER_PATH") else {
        return Ok(());
    };
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let (rss_kib, hwm_kib) = self_memory_kib();
    writeln!(
        file,
        "{name}\t0\t{}\t{}",
        rss_kib.map_or_else(|| "null".into(), |value| value.to_string()),
        hwm_kib.map_or_else(|| "null".into(), |value| value.to_string())
    )?;
    file.sync_all()?;
    if std::env::var("THINWALLET_KILL_AT_MARKER").as_deref() == Ok(name) {
        let pause_ms = std::env::var("THINWALLET_MARKER_PAUSE_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(15_000);
        std::thread::sleep(Duration::from_millis(pause_ms));
    }
    Ok(())
}

fn self_memory_kib() -> (Option<u64>, Option<u64>) {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return (None, None);
    };
    let value = |name: &str| {
        status.lines().find_map(|line| {
            let rest = line.strip_prefix(name)?;
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
    };
    (value("VmRSS:"), value("VmHWM:"))
}

fn inspect_token_store(root: &Path, log_size: usize) -> Result<()> {
    let (binding, _bases, _external_token_id, _seed) = token_material(log_size)?;
    let mut token_id = [0u8; 16];
    token_id[..8].copy_from_slice(&(log_size as u64).to_le_bytes());
    token_id[8..].copy_from_slice(&0x563250424d4fu64.to_le_bytes());
    let store = TokenStore::open(
        root,
        Box::new(SoftwareTokenStoreKeyProvider::new(
            "software-test-key-v1",
            [0x42; 32],
        )),
        Box::new(SoftwareCrashConsistentProvider),
        [0x24; 32],
    )
    .map_err(|error| anyhow!(error.to_string()))?;
    let state = store.state(&token_id);
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "classification": "TOKEN_STORE_RECOVERY_INSPECTION",
            "root": root,
            "token_id_digest": sha256(&token_id),
            "state": state.map(|value| format!("{value:?}").to_uppercase()),
            "journal_sequence": store.journal_state().sequence,
            "journal_head_hash": hex(&store.journal_state().head_hash),
            "binding_digest": hex(&binding.basis_digest),
            "rollback_classification": store.rollback_classification(),
        }))?
    );
    Ok(())
}

fn patched_run(mode: &str, log_size: usize) -> Result<RunResult> {
    let total_request_wall_start = thinwallet_instrumentation::duration_time_ns();
    let total_request_cpu_start = local_process_cpu_ns();
    let measurement_scope_guard = begin_prover_measurement_scope()?;
    let n = 1usize << log_size;
    let q = 1usize << (log_size / 2);
    let m = 1usize << (log_size - log_size / 2);
    let fs3 = std::env::var("LIBSPARTAN_MULTI_TARGET_STREAMING").as_deref() == Ok("1");
    let fs7 = std::env::var("LIBSPARTAN_CREDENTIAL_STREAMING").as_deref() == Ok("1");
    let configured_budget = fs3
        .then(patched::memory_budget::ProverMemoryBudget::from_env)
        .transpose()
        .map_err(|error| anyhow!("FS3 budget configuration rejected: {error}"))?;
    if fs3 {
        let budget = configured_budget.expect("FS3 budget missing");
        let fs4 = std::env::var("LIBSPARTAN_ACTIVE_STATE_STREAMING").as_deref() == Ok("1");
        let fs5 = std::env::var("LIBSPARTAN_TRANSCRIPT_RECOMPUTE").as_deref() == Ok("1");
        let fs6 = std::env::var("LIBSPARTAN_STREAMING_DEREFERENCE").as_deref() == Ok("1");
        let plan = if fs7 {
            None
        } else if fs6 {
            Some(patched::budget_planner::plan_fs6(
                n,
                budget,
                0,
                0,
                "local-pbmo",
            ))
        } else if fs5 {
            Some(patched::budget_planner::plan_fs5(
                n,
                budget,
                0,
                0,
                "local-pbmo",
            ))
        } else if fs4 {
            Some(patched::budget_planner::plan_fs4(
                n,
                budget,
                0,
                0,
                "local-pbmo",
            ))
        } else {
            Some(patched::budget_planner::plan(n, budget, 0, 0, "local-pbmo"))
        };
        if let Some(plan) = plan {
            let plan = plan.map_err(|error| anyhow!("FS3 controlled plan rejection: {error}"))?;
            if let Some(path) = std::env::var_os("V3B_PLAN_REPORT_PATH") {
                std::fs::write(path, serde_json::to_vec_pretty(&plan)?)?;
            }
        }
    }
    memory_stage("patched.before_relation_entries");
    let relation_phase = thinwallet_instrumentation::PhaseGuard::begin("relation_setup");
    let relation_entries_start = Instant::now();
    let (a, b, c, vars_bytes, input_bytes) = relation_entries(log_size);
    eprintln!(
        "V4F_PHASE_LATENCY phase=relation_entries_total elapsed_ms={:.6}",
        relation_entries_start.elapsed().as_secs_f64() * 1000.0
    );
    let num_inputs = input_bytes.len();
    let num_nz_entries = a.len().max(b.len()).max(c.len());
    if fs7 {
        let workload_name = std::env::var("THINWALLET_CREDENTIAL_WORKLOAD")
            .map_err(|_| anyhow!("FS7 requires a credential workload"))?;
        let workload = credential_workloads::profile_s::ProfileSWorkload::parse(&workload_name)
            .ok_or_else(|| anyhow!("FS7 requires Profile S"))?;
        let (credential_count, revocation_count, revocation_depth) = match workload {
            credential_workloads::profile_s::ProfileSWorkload::WK {
                credentials,
                revocation_count,
                revocation_depth,
                ..
            } => (credentials, revocation_count, revocation_depth),
            credential_workloads::profile_s::ProfileSWorkload::W4 => (2, 1, 8),
            credential_workloads::profile_s::ProfileSWorkload::W3 => (1, 1, 8),
            credential_workloads::profile_s::ProfileSWorkload::W1
            | credential_workloads::profile_s::ProfileSWorkload::W2 => (1, 0, 0),
        };
        let raw_constraint_count = a
            .iter()
            .chain(&b)
            .chain(&c)
            .map(|entry| entry.0)
            .max()
            .map(|row| row + 1);
        let plan = patched::budget_planner::plan_fs7(
            n,
            configured_budget.expect("FS7 budget missing"),
            patched::budget_planner::CredentialPlanShape {
                credential_count,
                revocation_count,
                revocation_depth,
                raw_constraint_count,
                padded_constraint_count: n,
                public_input_count: num_inputs,
                sparse_nonzero_entry_count: a.len() + b.len() + c.len(),
                max_sparse_matrix_entries: num_nz_entries,
                q,
                m,
            },
            0,
            0,
            if mode == "malicious" {
                "local-pbmo-fs7-M4"
            } else {
                "local-pbmo-fs7-M3"
            },
        )
        .map_err(|error| anyhow!("FS7 controlled plan rejection: {error}"))?;
        if let Some(path) = std::env::var_os("V3B_PLAN_REPORT_PATH") {
            std::fs::write(path, serde_json::to_vec_pretty(&plan)?)?;
        }
    }
    let mut relation = Some((a, b, c));
    memory_stage("patched.after_relation_entries");
    let instance_start = Instant::now();
    let mut inst = Some({
        let _memory_scope = memory_trace::scope(&INSTANCE_STATE);
        let (a, b, c) = relation.as_ref().unwrap();
        patched::Instance::new(n, n, num_inputs, a, b, c).map_err(debug_err)?
    });
    drop(relation_phase);
    eprintln!(
        "V4F_PHASE_LATENCY phase=instance_finalization elapsed_ms={:.6}",
        instance_start.elapsed().as_secs_f64() * 1000.0
    );
    memory_stage("patched.after_instance");
    let witness_phase = thinwallet_instrumentation::PhaseGuard::begin("witness_construction");
    let assignment_start = Instant::now();
    let vars = {
        let _memory_scope = memory_trace::scope(&ASSIGNMENT_STATE);
        patched::VarsAssignment::new(&vars_bytes).map_err(debug_err)?
    };
    drop(vars_bytes);
    let inputs = patched::InputsAssignment::new(&input_bytes).map_err(debug_err)?;
    drop(witness_phase);
    eprintln!(
        "V4F_PHASE_LATENCY phase=assignment_preparation elapsed_ms={:.6}",
        assignment_start.elapsed().as_secs_f64() * 1000.0
    );
    memory_stage("patched.after_assignments");
    let initialization_phase =
        thinwallet_instrumentation::PhaseGuard::begin("prover_initialization");
    let gens = {
        let _memory_scope = memory_trace::scope(&GENERATOR_STATE);
        patched::SNARKGens::new(n, n, num_inputs, num_nz_entries)
    };
    memory_stage("patched.after_gens");
    let encode_start = Instant::now();
    let (comm, decomm) = {
        let _memory_scope = memory_trace::scope(&ENCODE_STATE);
        patched::SNARK::encode(inst.as_ref().unwrap(), &gens)
    };
    drop(initialization_phase);
    eprintln!(
        "V4F_PHASE_LATENCY phase=instance_encoding elapsed_ms={:.6}",
        encode_start.elapsed().as_secs_f64() * 1000.0
    );
    memory_stage("patched.after_encode");
    let bases = {
        let _memory_scope = memory_trace::scope(&PBMO_STATE);
        libspartan_private_basis(m)
    };
    memory_stage("patched.after_pbmo_basis");
    if bases.len() != m {
        return Err(anyhow!("unexpected basis length {} != {m}", bases.len()));
    }
    let binding = TokenBinding {
        basis_digest: basis_digest(&bases),
        backend_revision: BACKEND_REVISION.into(),
        relation_shape: RelationShape {
            relation_id: relation_id(log_size),
            logical_commitment_id: "dense_mlpoly.private_commit.0".into(),
            layout_version: "libspartan-fragmented-v1".into(),
        },
        q: q as u32,
        m: m as u32,
    };
    let mut token_id = [0u8; 16];
    token_id[..8].copy_from_slice(&(log_size as u64).to_le_bytes());
    token_id[8..].copy_from_slice(&0x563250424d4fu64.to_le_bytes());
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(0x5eed0000u64 + log_size as u64).to_le_bytes());
    let pbmo_mode = matches!(mode, "semi" | "malicious");
    let require_pregenerated =
        std::env::var("THINWALLET_REQUIRE_PREGENERATED_TOKEN").as_deref() == Ok("1");
    if require_pregenerated && !pbmo_mode {
        return Err(anyhow!(
            "pre-generated token mode is only valid for PBMO execution"
        ));
    }
    let token_load_phase = thinwallet_instrumentation::PhaseGuard::begin("pbmo_token_load");
    let token_store_root = if pbmo_mode {
        Some(
            std::env::var_os("THINWALLET_TOKEN_STORE_ROOT")
                .map(PathBuf::from)
                .or_else(|| {
                    (!require_pregenerated).then(|| {
                        let stamp = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos();
                        PathBuf::from(format!(
                            "results/integration-token-stores/{log_size}-{mode}-{stamp}"
                        ))
                    })
                })
                .ok_or_else(|| {
                    anyhow!("THINWALLET_TOKEN_STORE_ROOT is required in pre-generated mode")
                })?,
        )
    } else {
        None
    };
    let mut token_size_bytes = None;
    let mut token_selected_id_sha256 = None;
    let mut available_token = None;
    if pbmo_mode && require_pregenerated {
        let context_phase =
            thinwallet_instrumentation::PhaseGuard::begin("token_context_validation");
        thinwallet_instrumentation::increment_counter("token_context_validation_calls", 1);
        let validated = validate_phase5b_token_context(
            token_store_root.as_ref().expect("PBMO token store root"),
            &binding,
        );
        let (selected, encoded_bytes, selected_hash) = match validated {
            Ok(value) => value,
            Err(error) => {
                thinwallet_instrumentation::increment_counter(
                    "token_context_validation_failures",
                    1,
                );
                return Err(error);
            }
        };
        drop(context_phase);
        token_id = selected;
        token_size_bytes = Some(encoded_bytes as usize);
        token_selected_id_sha256 = Some(selected_hash);
        thinwallet_instrumentation::increment_counter("pregenerated_token_load_calls", 1);
        thinwallet_instrumentation::increment_counter("pbmo_pregenerated_token_load_calls", 1);
        thinwallet_instrumentation::increment_counter(
            "pregenerated_token_load_bytes",
            encoded_bytes,
        );
        phase_marker("TOKEN_SELECTED")?;
    } else if pbmo_mode {
        let _memory_scope = memory_trace::scope(&PBMO_STATE);
        let generation_cpu_started = local_process_cpu_ns();
        let generation_started = Instant::now();
        let token = Token::generate_with_material(binding.clone(), &bases, token_id, seed)
            .map_err(|e| anyhow!(e.to_string()))?;
        let generation_wall_ns = generation_started.elapsed().as_nanos() as u64;
        let generation_cpu_ns = local_process_cpu_ns().saturating_sub(generation_cpu_started);
        thinwallet_instrumentation::increment_counter("token_generation_calls", 1);
        thinwallet_instrumentation::increment_counter("pbmo_token_generation_calls", 1);
        thinwallet_instrumentation::increment_counter(
            "token_generation_wall_ns",
            generation_wall_ns,
        );
        thinwallet_instrumentation::increment_counter("token_generation_cpu_ns", generation_cpu_ns);
        thinwallet_instrumentation::increment_counter(
            "token_generation_msm_calls",
            binding.q.into(),
        );
        thinwallet_instrumentation::increment_counter(
            "token_generation_msm_terms",
            u64::from(binding.q) * u64::from(binding.m),
        );
        thinwallet_instrumentation::increment_counter(
            "online_correction_msm_calls",
            binding.q.into(),
        );
        thinwallet_instrumentation::increment_counter(
            "pbmo_online_correction_msm_calls",
            binding.q.into(),
        );
        thinwallet_instrumentation::increment_counter(
            "online_correction_msm_terms",
            u64::from(binding.q) * u64::from(binding.m),
        );
        token_size_bytes = Some(
            token
                .encode(
                    &SoftwareTokenStoreKeyProvider::new("software-test-key-v1", [0x42; 32]),
                    &mut StdRng::seed_from_u64(0x0056_3254_4f4b_454e + log_size as u64),
                )
                .map_err(|e| anyhow!(e.to_string()))?
                .len(),
        );
        token_selected_id_sha256 = Some(sha256(&token.token_id));
        available_token = Some(token);
    }
    let chunk_size = 64usize.min(m);
    let context = PbmoContext {
        protocol_version: PROTOCOL_VERSION,
        session_id: std::env::var("THINWALLET_LOGICAL_INVOCATION_ID_HEX")
            .unwrap_or_else(|_| format!("phase-v2-{log_size}-{mode}")),
        proof_id: std::env::var("THINWALLET_LOGICAL_CIRCUIT_ID_HEX")
            .unwrap_or_else(|_| format!("proof-{log_size}-{mode}")),
        token_id: pbmo_mode.then_some(token_id),
        logical_commitment_id: "dense_mlpoly.private_commit.0".into(),
        basis_digest: binding.basis_digest,
        backend_revision: BACKEND_REVISION.into(),
        relation_shape: format!(
            "{}:{}",
            binding.relation_shape.relation_id, binding.relation_shape.layout_version
        ),
        expected_chunks: (q * m.div_ceil(chunk_size)) as u32,
    };
    let mut lifecycle_rng = StdRng::seed_from_u64(0x5632_0000 + log_size as u64);
    if pbmo_mode {
        reset_token_durability_metrics();
    }
    let mut token_store = if pbmo_mode {
        let root = token_store_root.as_ref().expect("PBMO token store root");
        let mut store = TokenStore::open(
            root,
            Box::new(SoftwareTokenStoreKeyProvider::new(
                "software-test-key-v1",
                [0x42; 32],
            )),
            Box::new(SoftwareCrashConsistentProvider),
            [0x24; 32],
        )
        .map_err(|e| anyhow!(e.to_string()))?;
        if require_pregenerated {
            if store.state(&token_id) != Some(TokenState::Available) {
                return Err(anyhow!(
                    "selected pre-generated token is not AVAILABLE in durable journal"
                ));
            }
        } else {
            store
                .insert(
                    available_token
                        .as_ref()
                        .ok_or_else(|| anyhow!("PBMO token generation was skipped"))?,
                    &mut lifecycle_rng,
                )
                .map_err(|e| anyhow!(e.to_string()))?;
        }
        Some(store)
    } else {
        None
    };
    let request_digest = pbmo_mode
        .then(|| context_binding_digest(&context, q, m))
        .transpose()
        .map_err(|error| anyhow!(error.to_string()))?;
    let token = if let Some(store) = token_store.as_mut() {
        let reserve_phase = thinwallet_instrumentation::PhaseGuard::begin("token_reserve");
        phase_marker("RESERVE_START")?;
        let reserved = store
            .reserve(
                &token_id,
                &binding,
                binding.context_digest(),
                &context.proof_id,
                &context.session_id,
                request_digest.expect("PBMO request digest"),
                &mut lifecycle_rng,
            )
            .map_err(|e| anyhow!(e.to_string()))?;
        phase_marker("RESERVE_DURABLE")?;
        drop(reserve_phase);
        Some(reserved)
    } else {
        available_token.take()
    };
    let mut lifecycle_attempt =
        if let (Some(store), Some(reserved)) = (token_store.take(), token.as_ref()) {
            Some(ActiveTokenReservation::new(store, reserved, lifecycle_rng)?)
        } else {
            None
        };
    if lifecycle_attempt.is_some() {
        phase_marker("AFTER_RESERVATION")?;
    }
    drop(token_load_phase);
    let provider = provider_for(mode, bases, token)?;
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    let start = Instant::now();
    if fs3 {
        drop(relation.take());
        release_allocator_pages();
        memory_stage("patched.after_relation_release");
    }
    let (proof, report) = {
        let _memory_scope = memory_trace::scope(&PROVE_STATE);
        let _audit = thinwallet_instrumentation::begin_prover_audit();
        with_full_pbmo_provider(
            FullPbmoRunConfig {
                context,
                chunk_size,
                provider,
            },
            || {
                if fs3 {
                    patched::SNARK::prove_owned(
                        inst.take().unwrap(),
                        &comm,
                        &decomm,
                        vars,
                        &inputs,
                        &gens,
                        &mut transcript,
                    )
                } else {
                    patched::SNARK::prove(
                        inst.as_ref().unwrap(),
                        &comm,
                        &decomm,
                        vars,
                        &inputs,
                        &gens,
                        &mut transcript,
                    )
                }
            },
        )
    };
    memory_stage("patched.after_prove");
    let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
    eprintln!("V4F_PHASE_LATENCY phase=total_prove elapsed_ms={prove_ms:.6}");
    if lifecycle_attempt.is_some() {
        phase_marker("AFTER_PROOF_BEFORE_SPENT")?;
    }
    if !report.selected || report.q != q || report.m != m {
        return Err(anyhow!("full commitment provider was not selected"));
    }
    if let Some(metrics) = report.metrics.as_ref() {
        thinwallet_instrumentation::increment_counter("server_row_msm_calls", metrics.q as u64);
        thinwallet_instrumentation::increment_counter(
            "pbmo_server_row_msm_calls",
            metrics.q as u64,
        );
        thinwallet_instrumentation::increment_counter(
            "server_row_msm_terms",
            metrics.server_group_terms,
        );
        thinwallet_instrumentation::increment_counter(
            "pbmo_server_row_msm_terms",
            metrics.server_group_terms,
        );
        thinwallet_instrumentation::increment_counter(
            "scalar_mask_additions",
            metrics.client_mask_field_ops,
        );
        thinwallet_instrumentation::increment_counter(
            "serialized_scalar_bytes",
            metrics.server_group_terms.saturating_mul(32),
        );
        thinwallet_instrumentation::increment_counter(
            "spool_bytes_written",
            metrics.spool_bytes_written,
        );
        thinwallet_instrumentation::increment_counter("spool_bytes_read", metrics.spool_bytes_read);
        if metrics.local_check_msm_terms > 0 {
            thinwallet_instrumentation::increment_counter("aggregate_check_msm_calls", 1);
            thinwallet_instrumentation::increment_counter(
                "aggregate_check_msm_terms",
                metrics.local_check_msm_terms,
            );
            thinwallet_instrumentation::increment_counter(
                "scalar_aggregate_multiply_adds",
                metrics.aggregate_field_ops / 2,
            );
        }
    }
    let mut execution_counters = thinwallet_instrumentation::counters_snapshot();
    let online_generation_assertions_passed = require_pregenerated.then(|| {
        execution_counters
            .get("token_generation_calls")
            .copied()
            .unwrap_or_default()
            == 0
            && execution_counters
                .get("token_generation_msm_calls")
                .copied()
                .unwrap_or_default()
                == 0
            && execution_counters
                .get("online_correction_msm_calls")
                .copied()
                .unwrap_or_default()
                == 0
            && execution_counters
                .get("pregenerated_token_load_calls")
                .copied()
                .unwrap_or_default()
                == 1
    });
    if online_generation_assertions_passed == Some(false) {
        return Err(anyhow!("ONLINE_SCOPE_CONTAMINATED"));
    }
    let (sat_proof_digest, eval_proof_digest) = proof.phase_component_digests();
    let serialization_phase = thinwallet_instrumentation::PhaseGuard::begin("proof_serialization");
    let bytes = bincode::serialize(&proof)?;
    drop(serialization_phase);
    let measurement_scope = measurement_scope_guard.finish();
    if !measurement_scope.valid_measurement_scope {
        return Err(anyhow!("invalid_measurement_scope"));
    }
    let mut patched_verifier_transcript = Transcript::new(TRANSCRIPT_LABEL);
    let verification_phase = thinwallet_instrumentation::PhaseGuard::begin("verification");
    let patched_accepts = {
        let _memory_scope = memory_trace::scope(&VERIFY_STATE);
        proof
            .verify(&comm, &inputs, &mut patched_verifier_transcript, &gens)
            .is_ok()
    };
    if std::env::var_os("THINWALLET_REMOTE_EVAL_ENDPOINT").is_some() {
        thinwallet_instrumentation::increment_counter("native_full_verify_calls", 1);
    }
    memory_stage("patched.after_patched_verify");
    let decomm_cpu_start = thinwallet_instrumentation::process_cpu_time_ns();
    let decomm_wall_start = Instant::now();
    let decomm_bytes = bincode::serialize(&decomm)?;
    let decomm_wall_ns = decomm_wall_start.elapsed().as_nanos() as u64;
    let decomm_cpu_ns =
        thinwallet_instrumentation::process_cpu_time_ns().saturating_sub(decomm_cpu_start);
    thinwallet_instrumentation::increment_counter(
        "r1cs_decomm_serialized_bytes",
        decomm_bytes.len() as u64,
    );
    thinwallet_instrumentation::increment_counter(
        "r1cs_decomm_serialization_wall_ns",
        decomm_wall_ns,
    );
    thinwallet_instrumentation::increment_counter(
        "r1cs_decomm_serialization_cpu_ns",
        decomm_cpu_ns,
    );
    drop(decomm_bytes);
    drop(decomm);
    drop(inst);
    memory_stage("patched.after_prover_state_drop");

    let force_native_rejection =
        std::env::var("THINWALLET_TEST_FORCE_NATIVE_VERIFY_REJECT").as_deref() == Ok("1");
    let original_accepts = if lifecycle_attempt.is_none()
        && std::env::var("THINWALLET_DEFER_UPSTREAM_VERIFY").as_deref() == Ok("1")
    {
        memory_stage("patched.upstream_verify_deferred");
        None
    } else {
        thinwallet_instrumentation::mark_verifier_preprocessing();
        let (baseline_a, baseline_b, baseline_c) = relation.take().unwrap_or_else(|| {
            let (a, b, c, _, _) = relation_entries(log_size);
            (a, b, c)
        });
        let baseline_inst = {
            let _memory_scope = memory_trace::scope(&INSTANCE_STATE);
            baseline::Instance::new(n, n, num_inputs, &baseline_a, &baseline_b, &baseline_c)
                .map_err(debug_err)?
        };
        let baseline_input_bytes = if force_native_rejection {
            vec![scalar_bytes(1)]
        } else {
            input_bytes.clone()
        };
        let baseline_inputs =
            baseline::InputsAssignment::new(&baseline_input_bytes).map_err(debug_err)?;
        let baseline_gens = {
            let _memory_scope = memory_trace::scope(&GENERATOR_STATE);
            baseline::SNARKGens::new(n, n, num_inputs, num_nz_entries)
        };
        let (baseline_comm, _) = {
            let _memory_scope = memory_trace::scope(&ENCODE_STATE);
            baseline::SNARK::encode(&baseline_inst, &baseline_gens)
        };
        let baseline_proof: baseline::SNARK = bincode::deserialize(&bytes)?;
        let mut baseline_transcript = Transcript::new(TRANSCRIPT_LABEL);
        let accepted = {
            let _memory_scope = memory_trace::scope(&VERIFY_STATE);
            baseline_proof
                .verify(
                    &baseline_comm,
                    &baseline_inputs,
                    &mut baseline_transcript,
                    &baseline_gens,
                )
                .is_ok()
        };
        if force_native_rejection {
            eprintln!("SECTION6_FORCED_UNCHANGED_NATIVE_VERIFY_ACCEPTED={accepted}");
        }
        memory_stage("patched.after_original_verify");
        Some(accepted)
    };
    drop(verification_phase);
    if lifecycle_attempt.is_some() && (!patched_accepts || original_accepts != Some(true)) {
        return Err(anyhow!("unchanged local native full verification rejected"));
    }
    let durable_token_state = if let Some(attempt) = lifecycle_attempt.as_mut() {
        phase_marker("AFTER_FULL_VERIFICATION_BEFORE_SPENT")?;
        let state = attempt.mark_spent()?;
        if state != TokenState::Spent {
            return Err(anyhow!("unexpected terminal token state"));
        }
        phase_marker("AFTER_SPENT")?;
        phase_marker("TOKEN_FINALIZED")?;
        Some("SPENT".into())
    } else {
        None
    };
    if let Some(path) = std::env::var_os("THINWALLET_PROOF_OUT") {
        fs::write(path, &bytes)?;
    }
    if std::env::var_os("THINWALLET_REMOTE_EVAL_ENDPOINT").is_some() {
        thinwallet_instrumentation::increment_counter(
            "remote_eval_final_proof_released",
            u64::from(patched_accepts && original_accepts == Some(true)),
        );
    }
    let token_durability = pbmo_mode.then(token_durability_metrics);
    thinwallet_instrumentation::increment_counter(
        "total_request_wall_ns",
        thinwallet_instrumentation::duration_time_ns().saturating_sub(total_request_wall_start),
    );
    thinwallet_instrumentation::increment_counter(
        "total_request_cpu_ns",
        local_process_cpu_ns().saturating_sub(total_request_cpu_start),
    );
    execution_counters = thinwallet_instrumentation::counters_snapshot();
    Ok(RunResult {
        mode: mode.into(),
        log_size,
        relation_size: n,
        q,
        m,
        prove_ms,
        peak_rss_mb: peak_rss_mb(),
        proof_size_bytes: bytes.len(),
        token_size_bytes,
        proof_sha256: sha256(&bytes),
        spartan_randomness_mode: Some(
            std::env::var("THINWALLET_SPARTAN_RANDOMNESS_MODE")
                .unwrap_or_else(|_| "split-independent".into()),
        ),
        r1cs_sat_proof_sha256: Some(hex(&sat_proof_digest)),
        r1cs_eval_proof_sha256: Some(hex(&eval_proof_digest)),
        proof_deserialization_pass: bincode::deserialize::<patched::SNARK>(&bytes).is_ok(),
        patched_verifier_accepts: patched_accepts,
        original_upstream_verifier_accepts: original_accepts,
        full_commitment_report: Some(report),
        native_blinding_preserved_locally: true,
        verifier_source_modified: false,
        durable_token_state,
        token_path_classification: pbmo_mode.then(|| {
            if require_pregenerated {
                "EXTERNAL_PREGENERATED_AVAILABLE".into()
            } else {
                "TOKEN_GENERATION_IN_ONLINE_PATH".into()
            }
        }),
        token_selected_id_sha256,
        online_generation_assertions_passed,
        token_durable_sync_calls: token_durability.map(|metrics| metrics.sync_calls),
        token_durable_sync_ms: token_durability
            .map(|metrics| metrics.sync_time_ns as f64 / 1_000_000.0),
        execution_counters,
        audit_digests: thinwallet_instrumentation::audit_digests(),
        measurement_scope,
    })
}

fn debug_err(err: impl std::fmt::Debug) -> anyhow::Error {
    anyhow!("{err:?}")
}

#[allow(clippy::type_complexity)]
fn token_material(
    log_size: usize,
) -> Result<(
    TokenBinding,
    Vec<curve25519_dalek::ristretto::RistrettoPoint>,
    [u8; 16],
    [u8; 32],
)> {
    let q = 1usize << (log_size / 2);
    let m = 1usize << (log_size - log_size / 2);
    let bases = libspartan_private_basis(m);
    let binding = TokenBinding {
        basis_digest: basis_digest(&bases),
        backend_revision: BACKEND_REVISION.into(),
        relation_shape: RelationShape {
            relation_id: relation_id(log_size),
            logical_commitment_id: "dense_mlpoly.private_commit.0".into(),
            layout_version: "libspartan-fragmented-v1".into(),
        },
        q: q as u32,
        m: m as u32,
    };
    let mut token_id = [0u8; 16];
    token_id[..8].copy_from_slice(&(log_size as u64).to_le_bytes());
    token_id[8..].copy_from_slice(&0x5634414e4452u64.to_le_bytes());
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(0x5eed_a000u64 + log_size as u64).to_le_bytes());
    Ok((binding, bases, token_id, seed))
}

fn token_keys() -> SoftwareTokenStoreKeyProvider {
    SoftwareTokenStoreKeyProvider::new("software-test-key-v1", [0x42; 32])
}

fn generate_token(log_size: usize, path: &Path) -> Result<()> {
    let (binding, bases, token_id, seed) = token_material(log_size)?;
    let mut token = Token::generate_with_material(binding, &bases, token_id, seed)
        .map_err(|error| anyhow!(error.to_string()))?;
    token.creation_epoch = 0;
    let mut rng = StdRng::seed_from_u64(0x414e_4452 + log_size as u64);
    let bytes = token
        .encode(&token_keys(), &mut rng)
        .map_err(|error| anyhow!(error.to_string()))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, &bytes)?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "command": "generate-token",
            "path": path,
            "bytes": bytes.len(),
            "token_id_sha256": sha256(&token.token_id),
            "q": token.binding.q,
            "m": token.binding.m,
            "backend_revision": token.binding.backend_revision,
            "state": format!("{:?}", token.state),
        }))?
    );
    Ok(())
}

fn proc_kib(name: &str, path: &str) -> Option<u64> {
    fs::read_to_string(path).ok()?.lines().find_map(|line| {
        let (field, value) = line.split_once(':')?;
        (field == name)
            .then(|| value.split_whitespace().next()?.parse::<u64>().ok())
            .flatten()
    })
}

fn workload_log_size(name: &str) -> Result<(String, usize)> {
    use credential_workloads::profile_s::{minimum_profile_s_log, ProfileSWorkload};
    match name {
        "S-W1" => return Ok(("S-W1".to_owned(), 13)),
        "S-W4" => return Ok(("S-W4".to_owned(), 14)),
        _ => {}
    }
    let canonical = match name {
        "H0" => "WK_k8_r0_d0_none",
        "H1" => "WK_k52_r1_d32_sparse_merkle",
        "H2" => "WK_k8_r8_d32_sparse_merkle",
        other => other,
    };
    let workload = ProfileSWorkload::parse(canonical)
        .ok_or_else(|| anyhow!("unknown Profile S workload {name}"))?;
    Ok((workload.name(), minimum_profile_s_log(workload)))
}

fn prepare_phase5b_tokens(
    workload: &str,
    count: usize,
    token_store_root: &Path,
    public_invocation_descriptor: &str,
    context_domain_separation: &str,
    server_protocol_binding: &str,
    creation_build_hash: &str,
) -> Result<()> {
    if count == 0 {
        return Err(anyhow!("token count must be positive"));
    }
    for (name, value) in [
        ("public invocation descriptor", public_invocation_descriptor),
        ("context/domain separation", context_domain_separation),
        ("server/protocol binding", server_protocol_binding),
        ("creation build hash", creation_build_hash),
    ] {
        if value.trim().is_empty() {
            return Err(anyhow!("{name} must not be empty"));
        }
    }

    let (canonical, log_size) = workload_log_size(workload)?;
    std::env::set_var("THINWALLET_CREDENTIAL_WORKLOAD", &canonical);
    let (binding, bases, _, _) = token_material(log_size)?;
    let bound_invocation_descriptor = format!(
        "{public_invocation_descriptor}|relation={}:{}",
        binding.relation_shape.relation_id, binding.relation_shape.layout_version
    );
    let mut store = TokenStore::open(
        token_store_root,
        Box::new(token_keys()),
        Box::new(SoftwareCrashConsistentProvider),
        [0x24; 32],
    )
    .map_err(|error| anyhow!(error.to_string()))?;
    if store
        .journal_state()
        .token_states
        .values()
        .any(|state| matches!(state, TokenState::Available | TokenState::Reserved))
    {
        return Err(anyhow!(
            "token store already contains live tokens; refusing ambiguous batch append"
        ));
    }

    let mut materials = Vec::with_capacity(count);
    for _ in 0..count {
        let mut token_id = [0u8; 16];
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut token_id);
        OsRng.fill_bytes(&mut seed);
        materials.push((token_id, seed));
    }
    let mut records = materials
        .iter()
        .map(|(token_id, _)| Phase5bTokenRecord {
            token_id_hex: hex(token_id),
            token_id_sha256: sha256(token_id),
            token_state: "CREATING".into(),
            token_bytes: None,
            token_sha256: None,
        })
        .collect::<Vec<_>>();
    let manifest_payload =
        |publication_state: &str, records: Vec<Phase5bTokenRecord>| Phase5bManifestPayload {
            schema_version: PHASE5B_MANIFEST_SCHEMA.into(),
            artifact_version: PHASE5B_ARTIFACT_VERSION.into(),
            protocol_version: PROTOCOL_VERSION,
            curve_backend_identifier: BACKEND_REVISION.into(),
            workload_identifier: canonical.clone(),
            q: binding.q,
            m: binding.m,
            basis_hash: hex(&binding.basis_digest),
            public_invocation_descriptor: bound_invocation_descriptor.clone(),
            context_domain_separation: context_domain_separation.into(),
            server_protocol_binding: server_protocol_binding.into(),
            creation_build_hash: creation_build_hash.into(),
            publication_state: publication_state.into(),
            tokens: records,
        };
    // A CREATING manifest quarantines a partially generated batch. Only the
    // final atomic AVAILABLE publication is accepted by the online loader.
    write_phase5b_manifest(
        token_store_root,
        manifest_payload("CREATING", records.clone()),
    )?;

    let mut generation_records = Vec::with_capacity(count);
    for (token_index, (token_id, seed)) in materials.into_iter().enumerate() {
        let total_started = Instant::now();
        let generation_cpu_started = local_process_cpu_ns();
        let generation_started = Instant::now();
        let (token, generation) =
            Token::generate_with_material_profiled(binding.clone(), &bases, token_id, seed)
                .map_err(|error| anyhow!(error.to_string()))?;
        let generation_wall_ns = generation_started.elapsed().as_nanos() as u64;
        let generation_cpu_ns = local_process_cpu_ns().saturating_sub(generation_cpu_started);
        thinwallet_instrumentation::increment_counter("token_generation_calls", 1);
        thinwallet_instrumentation::increment_counter(
            "token_generation_wall_ns",
            generation_wall_ns,
        );
        thinwallet_instrumentation::increment_counter("token_generation_cpu_ns", generation_cpu_ns);
        thinwallet_instrumentation::increment_counter(
            "token_generation_msm_calls",
            u64::from(binding.q),
        );
        thinwallet_instrumentation::increment_counter(
            "token_generation_msm_terms",
            u64::from(binding.q) * u64::from(binding.m),
        );
        thinwallet_instrumentation::increment_counter(
            "offline_correction_msm_calls",
            u64::from(binding.q),
        );
        thinwallet_instrumentation::increment_counter(
            "offline_correction_msm_terms",
            u64::from(binding.q) * u64::from(binding.m),
        );

        let persist_started = Instant::now();
        let mut rng = OsRng;
        store
            .insert(&token, &mut rng)
            .map_err(|error| anyhow!(error.to_string()))?;
        let persist_ns = persist_started.elapsed().as_nanos() as u64;
        let path = phase5b_token_path(token_store_root, &token_id);
        let encoded = fs::read(&path)?;
        if store.state(&token_id) != Some(TokenState::Available) {
            return Err(anyhow!("new token was not durably published as AVAILABLE"));
        }
        records[token_index].token_state = "AVAILABLE".into();
        records[token_index].token_bytes = Some(encoded.len() as u64);
        records[token_index].token_sha256 = Some(sha256(&encoded));
        generation_records.push(serde_json::json!({
            "workload": canonical,
            "token_index": token_index,
            "token_id_sha256": sha256(&token_id),
            "q": binding.q,
            "m": binding.m,
            "q_times_m": u64::from(binding.q) * u64::from(binding.m),
            "generation_wall_ns": generation_wall_ns,
            "generation_cpu_ns": generation_cpu_ns,
            "prf_expansion_ns": generation.prf_expansion_ns,
            "field_reduction_ns": generation.field_reduction_ns,
            "correction_msm_total_ns": generation.correction_msm_total_ns,
            "correction_msm_per_row_ns": generation.correction_msm_per_row_ns,
            "persistence_ns": persist_ns,
            "total_ns": total_started.elapsed().as_nanos() as u64,
            "token_bytes": encoded.len(),
            "token_state": "AVAILABLE",
            "secret_material_logged": false,
        }));
    }
    write_phase5b_manifest(token_store_root, manifest_payload("AVAILABLE", records))?;
    let generation_report = serde_json::json!({
        "schema_version": "thinwallet-phase5b-token-generation-v1",
        "artifact_version": PHASE5B_ARTIFACT_VERSION,
        "instrumentation_profile": std::env::var("THINWALLET_INSTRUMENTATION_PROFILE")
            .unwrap_or_else(|_| "off".into()),
        "workload": canonical,
        "count": count,
        "records": generation_records,
        "plaintext_seed_mask_or_correction_material_logged": false,
    });
    let report_path = token_store_root.join("token_generation.json");
    let report_tmp = token_store_root.join("token_generation.json.tmp");
    let mut report_file = fs::File::create(&report_tmp)?;
    report_file.write_all(&serde_json::to_vec_pretty(&generation_report)?)?;
    report_file.sync_all()?;
    fs::rename(report_tmp, report_path)?;
    fs::File::open(token_store_root)?.sync_all()?;
    Ok(())
}

fn validate_phase5b_token_context(
    root: &Path,
    binding: &TokenBinding,
) -> Result<([u8; 16], u64, String)> {
    let required = |name: &str| {
        std::env::var(name).map_err(|_| anyhow!("missing required Phase 5B variable {name}"))
    };
    let workload = required("THINWALLET_CREDENTIAL_WORKLOAD")?;
    let workload = credential_workloads::profile_s::ProfileSWorkload::parse(&workload)
        .map(|value| value.name())
        .unwrap_or(workload);
    let invocation = required("THINWALLET_PHASE5B_INVOCATION_DESCRIPTOR")?;
    let context = required("THINWALLET_PHASE5B_CONTEXT")?;
    let server_binding = required("THINWALLET_PHASE5B_SERVER_PROTOCOL_BINDING")?;
    let creation_build_hash = required("THINWALLET_PHASE5B_CREATION_BUILD_HASH")?;
    let selected_hex = required("THINWALLET_PREGENERATED_TOKEN_ID_HEX")?;
    let token_id = parse_hex_array::<16>(&selected_hex)?;
    let manifest = read_phase5b_manifest(root)?;
    let payload = &manifest.payload;
    let expected_shape = format!(
        "{}:{}",
        binding.relation_shape.relation_id, binding.relation_shape.layout_version
    );
    let expected_invocation = format!("{invocation}|relation={expected_shape}");
    let checks = [
        (
            payload.schema_version == PHASE5B_MANIFEST_SCHEMA,
            "manifest schema",
        ),
        (
            payload.artifact_version == PHASE5B_ARTIFACT_VERSION,
            "artifact version",
        ),
        (
            payload.protocol_version == PROTOCOL_VERSION,
            "protocol version",
        ),
        (
            payload.curve_backend_identifier == BACKEND_REVISION,
            "curve/backend identifier",
        ),
        (
            payload.workload_identifier == workload,
            "workload identifier",
        ),
        (payload.q == binding.q && payload.m == binding.m, "q/m"),
        (
            payload.basis_hash == hex(&binding.basis_digest),
            "basis hash",
        ),
        (
            payload.public_invocation_descriptor == expected_invocation,
            "public invocation descriptor",
        ),
        (
            payload.context_domain_separation == context,
            "context/domain separation",
        ),
        (
            payload.server_protocol_binding == server_binding,
            "server/protocol binding",
        ),
        (
            payload.creation_build_hash == creation_build_hash,
            "creation build hash",
        ),
        (
            payload.publication_state == "AVAILABLE",
            "manifest publication state",
        ),
    ];
    if let Some((_, label)) = checks.iter().find(|(passed, _)| !passed) {
        return Err(anyhow!("pre-generated token context mismatch: {label}"));
    }
    let record = payload
        .tokens
        .iter()
        .find(|record| record.token_id_hex == selected_hex)
        .ok_or_else(|| anyhow!("selected token is absent from authenticated manifest"))?;
    if record.token_state != "AVAILABLE" {
        return Err(anyhow!("selected token is not published AVAILABLE"));
    }
    let path = phase5b_token_path(root, &token_id);
    let encoded = fs::read(&path)
        .map_err(|error| anyhow!("selected token file {}: {error}", path.display()))?;
    if record.token_bytes != Some(encoded.len() as u64)
        || record.token_sha256.as_deref() != Some(sha256(&encoded).as_str())
    {
        return Err(anyhow!("selected token checksum/size mismatch"));
    }
    Ok((
        token_id,
        encoded.len() as u64,
        record.token_id_sha256.clone(),
    ))
}

fn generate_profiled_tokens(workload: &str, count: usize, output_dir: &Path) -> Result<()> {
    if count == 0 {
        return Err(anyhow!("token count must be positive"));
    }
    let (canonical, log_size) = workload_log_size(workload)?;
    std::env::set_var("THINWALLET_CREDENTIAL_WORKLOAD", &canonical);
    fs::create_dir_all(output_dir)?;
    let (binding, bases, _, _) = token_material(log_size)?;
    let keys = token_keys();
    let mut records = Vec::with_capacity(count);
    for token_index in 0..count {
        let total_started = Instant::now();
        let random_started = Instant::now();
        let mut token_id = [0u8; 16];
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut token_id);
        OsRng.fill_bytes(&mut seed);
        let random_seed_generation_ns = random_started.elapsed().as_nanos() as u64;
        let (mut token, generation) =
            Token::generate_with_material_profiled(binding.clone(), &bases, token_id, seed)
                .map_err(|error| anyhow!(error.to_string()))?;
        token.creation_epoch = 0;
        let mut encoding_rng = OsRng;
        let (encoded, encoding) = token
            .encode_profiled(&keys, &mut encoding_rng)
            .map_err(|error| anyhow!(error.to_string()))?;
        let token_dir = output_dir.join(format!("token-{token_index:03}"));
        fs::create_dir_all(&token_dir)?;
        let path = token_dir.join("token.bin");
        thinwallet_instrumentation::register_temp_artifact(&path, "token_file");
        let write_started = Instant::now();
        let mut file = fs::File::create(&path)?;
        file.write_all(&encoded)?;
        let file_write_ns = write_started.elapsed().as_nanos() as u64;
        thinwallet_instrumentation::record_artifact_write(&path, encoded.len() as u64);
        let fsync_started = Instant::now();
        file.sync_all()?;
        fs::File::open(&token_dir)?.sync_all()?;
        let fsync_ns = fsync_started.elapsed().as_nanos() as u64;
        let decoded = Token::decode(&encoded, &keys).map_err(|error| anyhow!(error.to_string()))?;
        if decoded.state != TokenState::Available {
            return Err(anyhow!("generated token is not Available"));
        }
        let allocated_bytes = fs::metadata(&path).ok().map(|metadata| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                metadata.blocks() * 512
            }
            #[cfg(not(unix))]
            {
                metadata.len()
            }
        });
        records.push(serde_json::json!({
            "workload": canonical,
            "token_index": token_index,
            "q": binding.q,
            "m": binding.m,
            "q_times_m": u64::from(binding.q) * u64::from(binding.m),
            "random_seed_generation_ns": random_seed_generation_ns,
            "prf_expansion_ns": generation.prf_expansion_ns,
            "field_reduction_ns": generation.field_reduction_ns,
            "correction_msm_total_ns": generation.correction_msm_total_ns,
            "correction_msm_per_row_ns": generation.correction_msm_per_row_ns,
            "correction_encoding_ns": encoding.correction_encoding_ns,
            "metadata_encoding_ns": encoding.metadata_encoding_ns,
            "token_encryption_ns": encoding.token_encryption_ns,
            "file_write_ns": file_write_ns,
            "fsync_ns": fsync_ns,
            "total_ns": total_started.elapsed().as_nanos() as u64,
            "peak_vmhwm_kib": proc_kib("VmHWM", "/proc/self/status"),
            "pss_after_kib": proc_kib("Pss", "/proc/self/smaps_rollup"),
            "token_bytes": encoded.len(),
            "allocated_token_bytes": allocated_bytes,
            "token_state": "Available",
            "token_id_sha256": sha256(&token_id),
        }));
    }
    fs::write(
        output_dir.join("token_generation.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "thinwallet-phase3-token-generation-v1",
            "instrumentation_profile": std::env::var("THINWALLET_INSTRUMENTATION_PROFILE")
                .unwrap_or_else(|_| "off".into()),
            "workload": canonical,
            "count": count,
            "records": records,
            "plaintext_seed_or_mask_logged": false,
        }))?,
    )?;
    Ok(())
}

fn inspect_token(path: &Path) -> Result<()> {
    let bytes = fs::read(path)?;
    let token = Token::decode(&bytes, &token_keys()).map_err(|error| anyhow!(error.to_string()))?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "command": "inspect-token",
            "path": path,
            "bytes": bytes.len(),
            "token_id_sha256": sha256(&token.token_id),
            "q": token.binding.q,
            "m": token.binding.m,
            "basis_digest": hex(&token.binding.basis_digest),
            "backend_revision": token.binding.backend_revision,
            "state": format!("{:?}", token.state),
        }))?
    );
    Ok(())
}

fn verify_proof(path: &Path, log_size: usize) -> Result<()> {
    let n = 1usize << log_size;
    let bytes = fs::read(path)?;
    let proof: baseline::SNARK = bincode::deserialize(&bytes)?;
    let (a, b, c, _, inputs) = relation_entries(log_size);
    let num_inputs = inputs.len();
    let num_nz_entries = a.len().max(b.len()).max(c.len());
    let instance = baseline::Instance::new(n, n, num_inputs, &a, &b, &c).map_err(debug_err)?;
    let inputs = baseline::InputsAssignment::new(&inputs).map_err(debug_err)?;
    let gens = baseline::SNARKGens::new(n, n, num_inputs, num_nz_entries);
    let (commitment, _) = baseline::SNARK::encode(&instance, &gens);
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    let accepted = proof
        .verify(&commitment, &inputs, &mut transcript, &gens)
        .is_ok();
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "command": "verify-proof",
            "accepted": accepted,
            "proof_bytes": bytes.len(),
            "proof_sha256": sha256(&bytes),
            "verifier": "unchanged-upstream-libspartan-0.9.0",
        }))?
    );
    if accepted {
        Ok(())
    } else {
        Err(anyhow!("proof rejected"))
    }
}

fn proc_value(path: &str, prefix: &str) -> Option<String> {
    fs::read_to_string(path).ok()?.lines().find_map(|line| {
        line.strip_prefix(prefix)
            .map(|value| value.trim().to_owned())
    })
}

fn getprop(name: &str) -> Option<String> {
    let output = Command::new("getprop").arg(name).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn print_device_profile() -> Result<()> {
    let profile = serde_json::json!({
        "command": "print-device-profile",
        "abi": std::env::consts::ARCH,
        "os": std::env::consts::OS,
        "android_release": getprop("ro.build.version.release"),
        "android_sdk": getprop("ro.build.version.sdk"),
        "soc_model": getprop("ro.soc.model"),
        "kernel": fs::read_to_string("/proc/version").ok().map(|v| v.trim().to_owned()),
        "mem_total": proc_value("/proc/meminfo", "MemTotal:"),
        "cpu_hardware": proc_value("/proc/cpuinfo", "Hardware"),
        "backend_revision": BACKEND_REVISION,
    });
    println!("{}", serde_json::to_string(&profile)?);
    Ok(())
}

fn print_memory_profile() -> Result<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    let selected = [
        "VmRSS:",
        "VmHWM:",
        "RssAnon:",
        "RssFile:",
        "RssShmem:",
        "VmData:",
        "VmStk:",
    ];
    let mut values = serde_json::Map::new();
    for line in status.lines() {
        if let Some(key) = selected.iter().find(|prefix| line.starts_with(**prefix)) {
            values.insert(
                key.trim_end_matches(':').to_string(),
                serde_json::Value::String(line[key.len()..].trim().to_owned()),
            );
        }
    }
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "command": "print-memory-profile",
            "proc_status": values,
            "internal_accounted_peak_bytes": serde_json::Value::Null,
        }))?
    );
    Ok(())
}

fn run_security_tests() -> Result<()> {
    let (binding, bases, token_id, seed) = token_material(12)?;
    let token = Token::generate_with_material(binding, &bases, token_id, seed)
        .map_err(|error| anyhow!(error.to_string()))?;
    let mut rng = StdRng::seed_from_u64(0x5345_4355);
    let encoded = token
        .encode(&token_keys(), &mut rng)
        .map_err(|error| anyhow!(error.to_string()))?;
    let decoded =
        Token::decode(&encoded, &token_keys()).map_err(|error| anyhow!(error.to_string()))?;
    let mut corrupted = encoded.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    let tamper_rejected = Token::decode(&corrupted, &token_keys()).is_err();
    let duplicate_rejected = detect_duplicate_ids(&[decoded.clone(), decoded]).is_err();
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "command": "run-security-tests",
            "token_tamper_rejected": tamper_rejected,
            "duplicate_token_rejected": duplicate_rejected,
            "software_only_snapshot_rollback_not_prevented": true,
            "full_android_regression_requires_physical_device": true,
        }))?
    );
    if tamper_rejected && duplicate_rejected {
        Ok(())
    } else {
        Err(anyhow!("security smoke test failed"))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn describe_workload(name: &str) -> Result<()> {
    use credential_workloads::profile_s::{
        build_profile_s, minimum_profile_s_log, ProfileSMutation, ProfileSWorkload,
    };

    let canonical = match name {
        "H0" => "WK_k8_r0_d0_none",
        "H1" => "WK_k52_r1_d32_sparse_merkle",
        "H2" => "WK_k8_r8_d32_sparse_merkle",
        other => other,
    };
    let workload = ProfileSWorkload::parse(canonical)
        .ok_or_else(|| anyhow!("unknown Profile S workload {name}"))?;
    let log_size = minimum_profile_s_log(workload);
    let fixture = build_profile_s(workload, ProfileSMutation::Valid, 1usize << log_size)
        .map_err(|error| anyhow!(error))?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "requested_name": name,
            "canonical_name": workload.name(),
            "log_size": log_size,
            "metadata": fixture.metadata,
        }))?
    );
    Ok(())
}

fn main() -> Result<()> {
    let raw_args = std::env::args().skip(1).collect::<Vec<_>>();
    if raw_args.first().map(String::as_str) == Some("token-prepare") {
        let value = |flag: &str| -> Result<String> {
            let index = raw_args
                .iter()
                .position(|argument| argument == flag)
                .ok_or_else(|| anyhow!("missing {flag}"))?;
            raw_args
                .get(index + 1)
                .cloned()
                .ok_or_else(|| anyhow!("missing value for {flag}"))
        };
        let workload = value("--workload")?;
        let count = value("--count")?.parse::<usize>()?;
        let token_store = PathBuf::from(value("--token-store")?);
        let invocation = value("--invocation")?;
        let context = value("--context")?;
        let server_binding = value("--server-binding")?;
        let creation_build_hash = value("--creation-build-hash")?;
        let profile = raw_args
            .iter()
            .position(|argument| argument == "--instrumentation-profile")
            .and_then(|index| raw_args.get(index + 1))
            .cloned()
            .unwrap_or_else(|| "perf".into());
        if !matches!(profile.as_str(), "off" | "perf" | "android-perf" | "audit") {
            return Err(anyhow!("invalid instrumentation profile"));
        }
        std::env::set_var("THINWALLET_INSTRUMENTATION_PROFILE", &profile);
        std::env::set_var(
            "THINWALLET_EXPERIMENT_RUN_ID",
            format!("phase5b-token-{workload}-{count}"),
        );
        std::env::set_var(
            "THINWALLET_MEMORY_CSV_PATH",
            token_store.join("offline_memory.csv"),
        );
        std::env::set_var("THINWALLET_IO_CSV_PATH", token_store.join("offline_io.csv"));
        std::env::set_var(
            "THINWALLET_PHASES_PATH",
            token_store.join("offline_phases.jsonl"),
        );
        std::env::set_var(
            "THINWALLET_COUNTERS_PATH",
            token_store.join("offline_execution_counters.json"),
        );
        std::env::set_var(
            "THINWALLET_TEMP_ARTIFACTS_PATH",
            token_store.join("offline_temp_artifacts.json"),
        );
        std::env::set_var("THINWALLET_EXPERIMENT_TEMP_DIR", &token_store);
        thinwallet_instrumentation::initialize();
        let sample_ms = std::env::var("THINWALLET_METRICS_SAMPLE_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(100);
        let sampler = thinwallet_instrumentation::start_sampler(sample_ms);
        let result = prepare_phase5b_tokens(
            &workload,
            count,
            &token_store,
            &invocation,
            &context,
            &server_binding,
            &creation_build_hash,
        );
        thinwallet_instrumentation::flush_counters();
        drop(sampler);
        return result;
    }
    if raw_args.first().map(String::as_str) == Some("token-generate") {
        let value = |flag: &str| -> Result<String> {
            let index = raw_args
                .iter()
                .position(|argument| argument == flag)
                .ok_or_else(|| anyhow!("missing {flag}"))?;
            raw_args
                .get(index + 1)
                .cloned()
                .ok_or_else(|| anyhow!("missing value for {flag}"))
        };
        let workload = value("--workload")?;
        let count = value("--count")?.parse::<usize>()?;
        let output_dir = PathBuf::from(value("--output-dir")?);
        let profile = value("--instrumentation-profile").unwrap_or_else(|_| "perf".into());
        if !matches!(profile.as_str(), "off" | "perf" | "android-perf" | "audit") {
            return Err(anyhow!("invalid instrumentation profile"));
        }
        std::env::set_var("THINWALLET_INSTRUMENTATION_PROFILE", &profile);
        std::env::set_var(
            "THINWALLET_EXPERIMENT_RUN_ID",
            format!("token-{workload}-{count}"),
        );
        std::env::set_var("THINWALLET_MEMORY_CSV_PATH", output_dir.join("memory.csv"));
        std::env::set_var("THINWALLET_IO_CSV_PATH", output_dir.join("io.csv"));
        std::env::set_var("THINWALLET_PHASES_PATH", output_dir.join("phases.jsonl"));
        std::env::set_var(
            "THINWALLET_COUNTERS_PATH",
            output_dir.join("execution_counters.json"),
        );
        std::env::set_var(
            "THINWALLET_TEMP_ARTIFACTS_PATH",
            output_dir.join("temp_artifacts.json"),
        );
        std::env::set_var("THINWALLET_EXPERIMENT_TEMP_DIR", &output_dir);
        thinwallet_instrumentation::initialize();
        let sample_ms = std::env::var("THINWALLET_METRICS_SAMPLE_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(100);
        let sampler = thinwallet_instrumentation::start_sampler(sample_ms);
        let result = generate_profiled_tokens(&workload, count, &output_dir);
        thinwallet_instrumentation::flush_counters();
        drop(sampler);
        return result;
    }
    thinwallet_instrumentation::initialize();
    patched::memory_trace::initialize_trace();
    fs::create_dir_all("results")?;
    let mut args = raw_args.into_iter();
    let command = args.next().ok_or_else(|| anyhow!("expected command"))?;
    match command.as_str() {
        "generate-token" => {
            let log_size = args.next().unwrap_or_else(|| "12".into()).parse()?;
            let path = PathBuf::from(
                args.next()
                    .unwrap_or_else(|| "results/android-token.bin".into()),
            );
            return generate_token(log_size, &path);
        }
        "inspect-token" => {
            let path = PathBuf::from(args.next().ok_or_else(|| anyhow!("expected token path"))?);
            return inspect_token(&path);
        }
        "inspect-token-store" => {
            let root = PathBuf::from(args.next().ok_or_else(|| anyhow!("expected store root"))?);
            let log_size = args.next().unwrap_or_else(|| "12".into()).parse()?;
            return inspect_token_store(&root, log_size);
        }
        "verify-proof" => {
            let path = PathBuf::from(args.next().ok_or_else(|| anyhow!("expected proof path"))?);
            let log_size = args.next().unwrap_or_else(|| "12".into()).parse()?;
            return verify_proof(&path, log_size);
        }
        "run-security-tests" => return run_security_tests(),
        "print-memory-profile" => return print_memory_profile(),
        "print-device-profile" => return print_device_profile(),
        "describe-workload" => {
            let workload = args
                .next()
                .ok_or_else(|| anyhow!("expected Profile S workload"))?;
            return describe_workload(&workload);
        }
        _ => {}
    }
    let mode = match command.as_str() {
        "prove-native" => "upstream",
        "prove-pbmo-in-memory" => "malicious",
        "prove-fs2" => {
            std::env::set_var("LIBSPARTAN_FIXED_STREAMING", "1");
            "malicious"
        }
        "prove-fs3" => {
            std::env::set_var("LIBSPARTAN_FIXED_STREAMING", "1");
            std::env::set_var("LIBSPARTAN_MULTI_TARGET_STREAMING", "1");
            if let Ok(root) = std::env::var("THINWALLET_STATE_DIR") {
                std::env::set_var("V3B_STATE_DIR", root);
            }
            if let Ok(root) = std::env::var("THINWALLET_TEMP_DIR") {
                std::env::set_var("V3A_STATE_DIR", root);
            }
            if let Ok(mib) = std::env::var("THINWALLET_MEMORY_BUDGET_MIB") {
                let bytes = mib.parse::<u64>()? * 1024 * 1024;
                std::env::set_var("V3B_HARD_LIMIT_BYTES", bytes.to_string());
            }
            "malicious"
        }
        "prove-fs4" => {
            std::env::set_var("LIBSPARTAN_FIXED_STREAMING", "1");
            std::env::set_var("LIBSPARTAN_MULTI_TARGET_STREAMING", "1");
            std::env::set_var("LIBSPARTAN_ACTIVE_STATE_STREAMING", "1");
            if let Ok(root) = std::env::var("THINWALLET_STATE_DIR") {
                std::env::set_var("V3B_STATE_DIR", root);
            }
            if let Ok(root) = std::env::var("THINWALLET_TEMP_DIR") {
                std::env::set_var("V3A_STATE_DIR", root);
            }
            if let Ok(mib) = std::env::var("THINWALLET_MEMORY_BUDGET_MIB") {
                let bytes = mib.parse::<u64>()? * 1024 * 1024;
                std::env::set_var("V3B_HARD_LIMIT_BYTES", bytes.to_string());
            }
            "malicious"
        }
        "upstream" | "native" | "plain" | "semi" | "malicious" => command.as_str(),
        _ => return Err(anyhow!("unknown command {command}")),
    };
    let log_size = args
        .next()
        .ok_or_else(|| anyhow!("expected log size"))?
        .parse::<usize>()?;
    if ![12usize, 13, 14, 15, 16, 17, 18, 20].contains(&log_size) {
        return Err(anyhow!("unsupported log size"));
    }
    let result = if mode == "upstream" {
        upstream(log_size)?
    } else {
        patched_run(mode, log_size)?
    };
    let cleanup_phase = thinwallet_instrumentation::PhaseGuard::begin("cleanup");
    drop(cleanup_phase);
    thinwallet_instrumentation::flush_counters();
    if let Some(path) = std::env::var_os("THINWALLET_TEMP_STORAGE_OUT") {
        fs::write(
            path,
            serde_json::to_vec_pretty(&thinwallet_instrumentation::temp_storage_report(None))?,
        )?;
    }
    let path = std::env::var_os("THINWALLET_RESULT_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("results/v2_{log_size}_{mode}.json")));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, serde_json::to_vec_pretty(&result)?)?;
    println!("{}", path.display());
    Ok(())
}
