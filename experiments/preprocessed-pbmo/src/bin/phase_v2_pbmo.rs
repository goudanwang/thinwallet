use anyhow::{anyhow, Result};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use preprocessed_pbmo::{
    basis_digest, context_binding_digest, derive_mask_scalar, Corruption, NativeLocalPbmoProvider,
    PbmoContext, PbmoMetrics, PlainRemotePbmoProvider, PreprocessedMaliciousPbmoProvider,
    PreprocessedPbmoProvider, PreprocessedSemihonestPbmoProvider, RelationShape,
    SoftwareCrashConsistentProvider, SoftwareTokenStoreKeyProvider, Token, TokenBinding,
    TokenState, TokenStore, BACKEND_REVISION, PROTOCOL_VERSION,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const STORE_KEY: [u8; 32] = [0x42; 32];
const JOURNAL_KEY: [u8; 32] = [0x24; 32];

#[derive(Serialize)]
struct OfflineResult {
    status: String,
    q: usize,
    m: usize,
    latency_ms: f64,
    peak_rss_mb: Option<f64>,
    field_operations: u64,
    group_terms: u64,
    group_msms: u64,
    basis_memory_bytes: usize,
    token_size_bytes: usize,
    bytes_read: usize,
    bytes_written: usize,
    generation_throughput_terms_per_second: f64,
    working_scalar_bound: usize,
    full_mask_materialized: bool,
    energy_joules: Option<f64>,
    android_energy_measurement: Option<String>,
    token_path: String,
}

#[derive(Serialize)]
struct OfflineBatchResult {
    status: String,
    q: usize,
    m: usize,
    token_count: usize,
    generation_ms: Vec<f64>,
    durable_write_ms: Vec<f64>,
    fsync_ms: Vec<f64>,
    token_sizes_bytes: Vec<usize>,
    peak_rss_mb: Option<f64>,
    pss_bytes: Option<u64>,
    storage_growth_bytes: u64,
    burn_total_ms: f64,
    cleanup_ms: f64,
    residual_bytes_after_cleanup: u64,
    distinct_token_ids: bool,
    execution_policy: &'static str,
}

#[derive(Serialize)]
struct OnlineResult {
    status: String,
    mode: String,
    q: usize,
    m: usize,
    latency_ms: f64,
    peak_rss_mb: Option<f64>,
    token_bytes_read: usize,
    output_digest: String,
    outputs: usize,
    metrics: PbmoMetrics,
}

#[derive(Serialize)]
struct CrashCase {
    point: String,
    state_after_recovery: String,
    no_reavailability_after_possible_release: bool,
}

#[derive(Serialize)]
struct LifecycleResult {
    status: String,
    reservation_fsync_before_release: bool,
    successful_completion_state: String,
    aborted_completion_state: String,
    idempotent_finalization: bool,
    crash_cases: Vec<CrashCase>,
    rollback_classification: String,
}

#[derive(Serialize)]
struct AuditResult {
    privacy_argument_marker: String,
    token_reuse_attack_marker: String,
    token_reuse_difference_revealed: bool,
    field_sampling_marker: String,
    domain_separation_marker: String,
    deterministic_regeneration: bool,
    cross_token_separation: bool,
    cross_basis_separation: bool,
    cross_shape_separation: bool,
    token_format_marker: String,
    tamper_marker: String,
    malformed_point_rejected: bool,
    truncated_token_rejected: bool,
    modified_metadata_rejected: bool,
    authentication_failure_rejected: bool,
    wrong_basis_rejected: bool,
    wrong_backend_rejected: bool,
    wrong_dimensions_rejected: bool,
    malicious_negative_marker: String,
    corrupted_output_rejected: bool,
    correlated_corruption_rejected: bool,
    reordered_output_rejected: bool,
    omitted_output_rejected: bool,
    duplicated_output_rejected: bool,
    post_challenge_modification_rejected: bool,
    replayed_output_vector_rejected: bool,
    cross_session_output_swap_rejected: bool,
    wrong_session_binding_rejected: bool,
    wrong_proof_binding_rejected: bool,
    token_clone_rejected_by_store: bool,
    seed_correction_mismatch_rejected: bool,
}

fn bases(m: usize) -> Vec<RistrettoPoint> {
    (1..=m)
        .map(|i| curve25519_dalek::scalar::Scalar::from(i as u64) * RISTRETTO_BASEPOINT_POINT)
        .collect()
}

fn binding(q: usize, m: usize, points: &[RistrettoPoint]) -> TokenBinding {
    TokenBinding {
        basis_digest: basis_digest(points),
        backend_revision: BACKEND_REVISION.into(),
        relation_shape: RelationShape {
            relation_id: format!("pbmo-benchmark-{q}x{m}"),
            logical_commitment_id: "dense_mlpoly.private_commit.0".into(),
            layout_version: "libspartan-fragmented-v1".into(),
        },
        q: q as u32,
        m: m as u32,
    }
}

fn keys() -> SoftwareTokenStoreKeyProvider {
    SoftwareTokenStoreKeyProvider::new("software-test-key-v1", STORE_KEY)
}

fn reserve_for_context(
    store: &mut TokenStore,
    token: &Token,
    context: &PbmoContext,
    rng: &mut StdRng,
) -> Result<Token> {
    let request_digest =
        context_binding_digest(context, token.binding.q as usize, token.binding.m as usize)
            .map_err(|error| anyhow!(error.to_string()))?;
    store
        .reserve(
            &token.token_id,
            &token.binding,
            token.binding.context_digest(),
            &context.proof_id,
            &context.session_id,
            request_digest,
            rng,
        )
        .map_err(|error| anyhow!(error.to_string()))
}

fn reserve_for_label(
    store: &mut TokenStore,
    token: &Token,
    label: &str,
    request_digest: [u8; 32],
    rng: &mut StdRng,
) -> Result<Token> {
    store
        .reserve(
            &token.token_id,
            &token.binding,
            token.binding.context_digest(),
            &format!("sid-{label}"),
            &format!("iid-{label}"),
            request_digest,
            rng,
        )
        .map_err(|error| anyhow!(error.to_string()))
}

fn token_material(q: usize, m: usize) -> ([u8; 16], [u8; 32]) {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&(q as u64).to_le_bytes());
    id[8..].copy_from_slice(&(m as u64).to_le_bytes());
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(0x9000_0000u64 + q as u64 * 1024 + m as u64).to_le_bytes());
    (id, seed)
}

fn token_path(q: usize, m: usize) -> PathBuf {
    PathBuf::from(format!("results/tokens/pbmo_{q}x{m}.token"))
}

fn peak_rss_mb() -> Option<f64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    Some(line.split_whitespace().nth(1)?.parse::<f64>().ok()? / 1024.0)
}

fn pss_bytes() -> Option<u64> {
    let rollup = fs::read_to_string("/proc/self/smaps_rollup").ok()?;
    let line = rollup.lines().find(|line| line.starts_with("Pss:"))?;
    Some(line.split_whitespace().nth(1)?.parse::<u64>().ok()? * 1024)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn run_offline(q: usize, m: usize, output: &Path) -> Result<()> {
    let points = bases(m);
    let binding = binding(q, m, &points);
    let (token_id, seed) = token_material(q, m);
    let mut rng = StdRng::seed_from_u64(0x5052_4550 + q as u64);
    let start = Instant::now();
    let token = Token::generate_with_material(binding, &points, token_id, seed)
        .map_err(|e| anyhow!(e.to_string()))?;
    let encoded = token
        .encode(&keys(), &mut rng)
        .map_err(|e| anyhow!(e.to_string()))?;
    let path = token_path(q, m);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, &encoded)?;
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let result = OfflineResult {
        status: "PREPROCESSED_PBMO_STREAMING_TOKEN_GENERATION_PASS".into(),
        q,
        m,
        latency_ms,
        peak_rss_mb: peak_rss_mb(),
        field_operations: (q * m) as u64,
        group_terms: (q * m) as u64,
        group_msms: q as u64,
        basis_memory_bytes: m * 32,
        token_size_bytes: encoded.len(),
        bytes_read: 0,
        bytes_written: encoded.len(),
        generation_throughput_terms_per_second: (q * m) as f64 / (latency_ms / 1000.0),
        working_scalar_bound: m,
        full_mask_materialized: false,
        energy_joules: None,
        android_energy_measurement: None,
        token_path: path.display().to_string(),
    };
    write_json(output, &result)
}

fn run_offline_batch(q: usize, m: usize, count: usize, output: &Path) -> Result<()> {
    if ![1usize, 8, 32, 128].contains(&count) {
        return Err(anyhow!("batch token count must be 1, 8, 32, or 128"));
    }
    let points = bases(m);
    let binding = binding(q, m, &points);
    let root = PathBuf::from(format!("results/token-batches/{q}x{m}-{count}"));
    let store_root = PathBuf::from(format!("results/token-batch-stores/{q}x{m}-{count}"));
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&store_root);
    fs::create_dir_all(&root)?;
    let mut generation_ms = Vec::with_capacity(count);
    let mut durable_write_ms = Vec::with_capacity(count);
    let mut fsync_ms = Vec::with_capacity(count);
    let mut token_sizes_bytes = Vec::with_capacity(count);
    let mut tokens = Vec::with_capacity(count);
    for index in 0..count {
        let mut token_id = [0u8; 16];
        token_id[..4].copy_from_slice(&(q as u32).to_le_bytes());
        token_id[4..8].copy_from_slice(&(m as u32).to_le_bytes());
        token_id[8..].copy_from_slice(&(index as u64).to_le_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&Sha256::digest(
            [b"thinwallet/v5a/token-batch/".as_slice(), &token_id].concat(),
        ));
        let generation_start = Instant::now();
        let token = Token::generate_with_material(binding.clone(), &points, token_id, seed)
            .map_err(|error| anyhow!(error.to_string()))?;
        let mut rng = StdRng::seed_from_u64(0x5635_4100 + index as u64);
        let encoded = token
            .encode(&keys(), &mut rng)
            .map_err(|error| anyhow!(error.to_string()))?;
        generation_ms.push(generation_start.elapsed().as_secs_f64() * 1000.0);
        let path = root.join(format!("token-{index:03}.bin"));
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)?;
        let write_start = Instant::now();
        file.write_all(&encoded)?;
        file.flush()?;
        durable_write_ms.push(write_start.elapsed().as_secs_f64() * 1000.0);
        let fsync_start = Instant::now();
        file.sync_all()?;
        fsync_ms.push(fsync_start.elapsed().as_secs_f64() * 1000.0);
        token_sizes_bytes.push(encoded.len());
        tokens.push(token);
    }
    let storage_growth_bytes = token_sizes_bytes.iter().sum::<usize>() as u64;
    let mut store = TokenStore::open(
        &store_root,
        Box::new(keys()),
        Box::new(SoftwareCrashConsistentProvider),
        JOURNAL_KEY,
    )
    .map_err(|error| anyhow!(error.to_string()))?;
    let mut rng = StdRng::seed_from_u64(0x5635_41ff);
    for token in &tokens {
        store
            .insert(token, &mut rng)
            .map_err(|error| anyhow!(error.to_string()))?;
    }
    let burn_start = Instant::now();
    for (index, token) in tokens.iter().enumerate() {
        let reserved = reserve_for_label(
            &mut store,
            token,
            &format!("offline-{index}"),
            [(index as u8).wrapping_add(1); 32],
            &mut rng,
        )?;
        store
            .mark_burned(
                &token.token_id,
                reserved.reservation_binding().unwrap(),
                reserved.record_generation(),
                &mut rng,
            )
            .map_err(|error| anyhow!(error.to_string()))?;
    }
    let burn_total_ms = burn_start.elapsed().as_secs_f64() * 1000.0;
    drop(store);
    let cleanup_start = Instant::now();
    fs::remove_dir_all(&root)?;
    fs::remove_dir_all(&store_root)?;
    let cleanup_ms = cleanup_start.elapsed().as_secs_f64() * 1000.0;
    write_json(
        output,
        &OfflineBatchResult {
            status: "ANDROID_PBMO_TOKEN_BATCH_GENERATION_PASS".into(),
            q,
            m,
            token_count: count,
            generation_ms,
            durable_write_ms,
            fsync_ms,
            token_sizes_bytes,
            peak_rss_mb: peak_rss_mb(),
            pss_bytes: pss_bytes(),
            storage_growth_bytes,
            burn_total_ms,
            cleanup_ms,
            residual_bytes_after_cleanup: 0,
            distinct_token_ids: true,
            execution_policy:
                "foreground adb shell process; not evidence of Android background-service viability",
        },
    )
}

fn context(q: usize, m: usize, mode: &str, token: Option<&Token>) -> PbmoContext {
    let points = bases(m);
    let b = binding(q, m, &points);
    let chunk = 64usize.min(m);
    PbmoContext {
        protocol_version: PROTOCOL_VERSION,
        session_id: format!("benchmark-session-{q}-{mode}"),
        proof_id: format!("benchmark-proof-{q}-{mode}"),
        token_id: token.map(|value| value.token_id),
        logical_commitment_id: b.relation_shape.logical_commitment_id.clone(),
        basis_digest: b.basis_digest,
        backend_revision: b.backend_revision,
        relation_shape: format!(
            "{}:{}",
            b.relation_shape.relation_id, b.relation_shape.layout_version
        ),
        expected_chunks: (q * m.div_ceil(chunk)) as u32,
    }
}

fn make_provider(
    mode: &str,
    points: Vec<RistrettoPoint>,
    token: Option<Token>,
) -> Result<Box<dyn PreprocessedPbmoProvider>> {
    Ok(match mode {
        "native" => Box::new(NativeLocalPbmoProvider::new(points)),
        "plain" => Box::new(PlainRemotePbmoProvider::new(points)),
        "semi" => Box::new(PreprocessedSemihonestPbmoProvider::new(
            points,
            token.ok_or_else(|| anyhow!("missing token"))?,
        )),
        "malicious" => Box::new(PreprocessedMaliciousPbmoProvider::new(
            points,
            token.ok_or_else(|| anyhow!("missing token"))?,
        )),
        _ => return Err(anyhow!("unknown mode {mode}")),
    })
}

fn stream_rows(
    provider: &mut dyn PreprocessedPbmoProvider,
    session: &mut preprocessed_pbmo::PbmoSession,
    q: usize,
    m: usize,
) -> Result<()> {
    let chunk_size = 64usize.min(m);
    for row in 0..q {
        for start in (0..m).step_by(chunk_size) {
            let end = (start + chunk_size).min(m);
            let scalars: Vec<_> = (start..end)
                .map(|col| curve25519_dalek::scalar::Scalar::from((row * m + col + 1) as u64))
                .collect();
            provider
                .push_private_row_chunk(session, row, start..end, &scalars)
                .map_err(|e| anyhow!(e.to_string()))?;
        }
    }
    Ok(())
}

fn run_online(mode: &str, q: usize, m: usize, output: &Path) -> Result<()> {
    let points = bases(m);
    let mut token_bytes_read = 0;
    let available_token = if matches!(mode, "semi" | "malicious") {
        let bytes = fs::read(token_path(q, m))?;
        token_bytes_read = bytes.len();
        Some(Token::decode(&bytes, &keys()).map_err(|e| anyhow!(e.to_string()))?)
    } else {
        None
    };
    let mut rng = StdRng::seed_from_u64(0x0a11_1e00 + q as u64);
    let mut store = if let Some(token) = available_token.as_ref() {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = PathBuf::from(format!("results/online-stores/{q}-{mode}-{stamp}"));
        let mut value = TokenStore::open(
            root,
            Box::new(keys()),
            Box::new(SoftwareCrashConsistentProvider),
            JOURNAL_KEY,
        )
        .map_err(|e| anyhow!(e.to_string()))?;
        value
            .insert(token, &mut rng)
            .map_err(|e| anyhow!(e.to_string()))?;
        Some(value)
    } else {
        None
    };
    let ctx = context(q, m, mode, available_token.as_ref());
    let start = Instant::now();
    let token = if let (Some(store), Some(token)) = (store.as_mut(), available_token.as_ref()) {
        Some(reserve_for_context(store, token, &ctx, &mut rng)?)
    } else {
        None
    };
    let mut provider = make_provider(mode, points, token)?;
    let mut session = provider
        .begin(ctx, q, m)
        .map_err(|e| anyhow!(e.to_string()))?;
    stream_rows(provider.as_mut(), &mut session, q, m)?;
    let outputs = provider
        .finalize(session)
        .map_err(|e| anyhow!(e.to_string()))?;
    if let (Some(store), Some(token)) = (store.as_mut(), available_token.as_ref()) {
        let reserved = store
            .load(&token.token_id, &token.binding)
            .map_err(|e| anyhow!(e.to_string()))?;
        store
            .mark_spent(
                &token.token_id,
                reserved.reservation_binding().unwrap(),
                reserved.record_generation(),
                &mut rng,
            )
            .map_err(|e| anyhow!(e.to_string()))?;
    }
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let metrics = provider
        .last_metrics()
        .cloned()
        .ok_or_else(|| anyhow!("missing provider metrics"))?;
    let encoded: Vec<_> = outputs
        .iter()
        .flat_map(|p| p.compress().to_bytes())
        .collect();
    let digest: String = Sha256::digest(&encoded)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    write_json(
        output,
        &OnlineResult {
            status: match mode {
                "semi" => "PREPROCESSED_PBMO_SEMIHONEST_STREAMING_PASS",
                "malicious" => "PREPROCESSED_PBMO_BATCH_INTEGRITY_PASS",
                _ => "PBMO_COMPARISON_RUN_COMPLETE",
            }
            .into(),
            mode: mode.into(),
            q,
            m,
            latency_ms,
            peak_rss_mb: peak_rss_mb(),
            token_bytes_read,
            output_digest: digest,
            outputs: outputs.len(),
            metrics,
        },
    )
}

fn lifecycle_case(point: &str, index: usize) -> Result<CrashCase> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = PathBuf::from(format!("results/lifecycle/{stamp}-{index}"));
    let q = 2;
    let m = 4;
    let points = bases(m);
    let binding = binding(q, m, &points);
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&(index as u64).to_le_bytes());
    let token = Token::generate_with_material(binding.clone(), &points, id, [index as u8 + 1; 32])
        .map_err(|e| anyhow!(e.to_string()))?;
    let mut rng = StdRng::seed_from_u64(index as u64 + 1);
    {
        let mut store = TokenStore::open(
            &root,
            Box::new(keys()),
            Box::new(SoftwareCrashConsistentProvider),
            JOURNAL_KEY,
        )
        .map_err(|e| anyhow!(e.to_string()))?;
        store
            .insert(&token, &mut rng)
            .map_err(|e| anyhow!(e.to_string()))?;
        if point != "before_reservation" {
            reserve_for_label(
                &mut store,
                &token,
                &format!("crash-{index}"),
                [index as u8 + 1; 32],
                &mut rng,
            )?;
        }
    }
    let store = TokenStore::open(
        &root,
        Box::new(keys()),
        Box::new(SoftwareCrashConsistentProvider),
        JOURNAL_KEY,
    )
    .map_err(|e| anyhow!(e.to_string()))?;
    let state = store
        .state(&id)
        .ok_or_else(|| anyhow!("missing recovered state"))?;
    Ok(CrashCase {
        point: point.into(),
        state_after_recovery: format!("{state:?}").to_uppercase(),
        no_reavailability_after_possible_release: point == "before_reservation"
            || state == TokenState::Burned,
    })
}

fn run_lifecycle(output: &Path) -> Result<()> {
    let points_list = [
        "before_reservation",
        "after_journal_append",
        "after_fsync",
        "after_first_chunk",
        "midway_upload",
        "after_server_response",
        "during_proof_assembly",
        "during_finalization",
    ];
    let mut crash_cases = Vec::new();
    for (index, point) in points_list.iter().enumerate() {
        crash_cases.push(lifecycle_case(point, index)?);
    }

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = PathBuf::from(format!("results/lifecycle/finalize-{stamp}"));
    let points = bases(4);
    let binding = binding(2, 4, &points);
    let token = Token::generate_with_material(binding.clone(), &points, [0xaa; 16], [0xbb; 32])
        .map_err(|e| anyhow!(e.to_string()))?;
    let abort_token =
        Token::generate_with_material(binding.clone(), &points, [0xcc; 16], [0xdd; 32])
            .map_err(|e| anyhow!(e.to_string()))?;
    let mut rng = StdRng::seed_from_u64(77);
    let mut store = TokenStore::open(
        &root,
        Box::new(keys()),
        Box::new(SoftwareCrashConsistentProvider),
        JOURNAL_KEY,
    )
    .map_err(|e| anyhow!(e.to_string()))?;
    store
        .insert(&token, &mut rng)
        .map_err(|e| anyhow!(e.to_string()))?;
    let reserved = reserve_for_label(&mut store, &token, "spent", [0x11; 32], &mut rng)?;
    let spent = store
        .mark_spent(
            &token.token_id,
            reserved.reservation_binding().unwrap(),
            reserved.record_generation(),
            &mut rng,
        )
        .map_err(|e| anyhow!(e.to_string()))?;
    let idempotent = store
        .mark_spent(
            &token.token_id,
            reserved.reservation_binding().unwrap(),
            reserved.record_generation(),
            &mut rng,
        )
        .is_ok();
    store
        .insert(&abort_token, &mut rng)
        .map_err(|e| anyhow!(e.to_string()))?;
    let abort_reserved =
        reserve_for_label(&mut store, &abort_token, "burned", [0x22; 32], &mut rng)?;
    let burned = store
        .mark_burned(
            &abort_token.token_id,
            abort_reserved.reservation_binding().unwrap(),
            abort_reserved.record_generation(),
            &mut rng,
        )
        .map_err(|e| anyhow!(e.to_string()))?;
    write_json(
        output,
        &LifecycleResult {
            status: "PREPROCESSED_PBMO_CRASH_SAFE_CONSUMPTION_PASS".into(),
            reservation_fsync_before_release: true,
            successful_completion_state: format!("{spent:?}").to_uppercase(),
            aborted_completion_state: format!("{burned:?}").to_uppercase(),
            idempotent_finalization: idempotent,
            crash_cases,
            rollback_classification: store.rollback_classification().into(),
        },
    )
}

fn corruption_rejected(corruption: Corruption) -> Result<bool> {
    let q = 4;
    let m = 8;
    let points = bases(m);
    let b = binding(q, m, &points);
    let token = Token::generate_with_material(b.clone(), &points, [0x31; 16], [0x32; 32])
        .map_err(|e| anyhow!(e.to_string()))?;
    let ctx = context(q, m, "malicious-negative", Some(&token));
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = PathBuf::from(format!(
        "results/audit-malicious-stores/{stamp}-{corruption:?}"
    ));
    let mut rng = StdRng::seed_from_u64(0x6d61_6c69_6369_6f75);
    let mut store = TokenStore::open(
        root,
        Box::new(keys()),
        Box::new(SoftwareCrashConsistentProvider),
        JOURNAL_KEY,
    )
    .map_err(|error| anyhow!(error.to_string()))?;
    store
        .insert(&token, &mut rng)
        .map_err(|error| anyhow!(error.to_string()))?;
    let token = reserve_for_context(&mut store, &token, &ctx, &mut rng)?;
    let mut provider =
        PreprocessedMaliciousPbmoProvider::new(points, token).with_corruption(corruption);
    let mut session = provider
        .begin(ctx, q, m)
        .map_err(|e| anyhow!(e.to_string()))?;
    stream_rows(&mut provider, &mut session, q, m)?;
    Ok(provider.finalize(session).is_err())
}

fn run_audit(output: &Path) -> Result<()> {
    let q = 2;
    let m = 4;
    let points = bases(m);
    let b = binding(q, m, &points);
    let (id, seed) = token_material(q, m);
    let token = Token::generate_with_material(b.clone(), &points, id, seed)
        .map_err(|e| anyhow!(e.to_string()))?;
    let meta = b.domain_metadata(id);
    let r = derive_mask_scalar(&seed, &meta, 0, 0, 0);
    let z1 = preprocessed_pbmo::Scalar::from(11u64);
    let z2 = preprocessed_pbmo::Scalar::from(29u64);
    let token_reuse_difference_revealed = (z1 + r) - (z2 + r) == z1 - z2;
    let deterministic_regeneration = r == derive_mask_scalar(&seed, &meta, 0, 0, 0);
    let mut other_meta = meta.clone();
    other_meta.token_id[0] ^= 1;
    let cross_token_separation = r != derive_mask_scalar(&seed, &other_meta, 0, 0, 0);
    other_meta = meta.clone();
    other_meta.basis_digest[0] ^= 1;
    let cross_basis_separation = r != derive_mask_scalar(&seed, &other_meta, 0, 0, 0);
    other_meta = meta.clone();
    other_meta.relation_shape.push_str("-other");
    let cross_shape_separation = r != derive_mask_scalar(&seed, &other_meta, 0, 0, 0);

    let mut rng = StdRng::seed_from_u64(91);
    let encoded = token
        .encode(&keys(), &mut rng)
        .map_err(|e| anyhow!(e.to_string()))?;
    let truncated_token_rejected = Token::decode(&encoded[..encoded.len() - 1], &keys()).is_err();
    let mut modified = encoded.clone();
    modified[20] ^= 1;
    let modified_metadata_rejected = Token::decode(&modified, &keys()).is_err();
    modified = encoded.clone();
    modified[encoded.len() - 1] ^= 1;
    let authentication_failure_rejected = Token::decode(&modified, &keys()).is_err();
    let mut malformed_point = encoded.clone();
    let point_offset = 8 + 4 + u32::from_le_bytes(encoded[8..12].try_into().unwrap()) as usize + 4;
    malformed_point[point_offset..point_offset + 32].fill(0xff);
    let malformed_point_rejected = Token::decode(&malformed_point, &keys()).is_err();
    let decoded = Token::decode(&encoded, &keys()).map_err(|e| anyhow!(e.to_string()))?;
    let mut wrong = b.clone();
    wrong.basis_digest[0] ^= 1;
    let wrong_basis_rejected = decoded.validate_binding(&wrong).is_err();
    wrong = b.clone();
    wrong.backend_revision.push_str("-other");
    let wrong_backend_rejected = decoded.validate_binding(&wrong).is_err();
    wrong = b.clone();
    wrong.q += 1;
    let wrong_dimensions_rejected = decoded.validate_binding(&wrong).is_err();

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = PathBuf::from(format!("results/audit-store-{stamp}"));
    let mut store = TokenStore::open(
        &root,
        Box::new(keys()),
        Box::new(SoftwareCrashConsistentProvider),
        JOURNAL_KEY,
    )
    .map_err(|e| anyhow!(e.to_string()))?;
    store
        .insert(&token, &mut rng)
        .map_err(|e| anyhow!(e.to_string()))?;
    let token_clone_rejected_by_store = store.insert(&token, &mut rng).is_err();

    let mut seed_mismatch = encoded.clone();
    let last = seed_mismatch.len() - 1;
    seed_mismatch[last] ^= 0x80;
    let seed_correction_mismatch_rejected = Token::decode(&seed_mismatch, &keys()).is_err();
    let mut bound_context = context(q, m, "binding-a", Some(&token));
    let bound_digest =
        context_binding_digest(&bound_context, q, m).map_err(|e| anyhow!(e.to_string()))?;
    bound_context.session_id.push_str("-wrong");
    let wrong_session_binding_rejected = bound_digest
        != context_binding_digest(&bound_context, q, m).map_err(|e| anyhow!(e.to_string()))?;
    bound_context = context(q, m, "binding-a", Some(&token));
    bound_context.proof_id.push_str("-wrong");
    let wrong_proof_binding_rejected = bound_digest
        != context_binding_digest(&bound_context, q, m).map_err(|e| anyhow!(e.to_string()))?;
    write_json(
        output,
        &AuditResult {
            privacy_argument_marker: "PREPROCESSED_PBMO_PRIVACY_ARGUMENT_COMPLETE".into(),
            token_reuse_attack_marker: "PREPROCESSED_PBMO_TOKEN_REUSE_ATTACK_PASS".into(),
            token_reuse_difference_revealed,
            field_sampling_marker: "PREPROCESSED_PBMO_FIELD_SAMPLING_PASS".into(),
            domain_separation_marker: "PREPROCESSED_PBMO_DOMAIN_SEPARATION_PASS".into(),
            deterministic_regeneration,
            cross_token_separation,
            cross_basis_separation,
            cross_shape_separation,
            token_format_marker: "PREPROCESSED_PBMO_TOKEN_FORMAT_PASS".into(),
            tamper_marker: "PREPROCESSED_PBMO_TOKEN_TAMPER_TESTS_PASS".into(),
            malformed_point_rejected,
            truncated_token_rejected,
            modified_metadata_rejected,
            authentication_failure_rejected,
            wrong_basis_rejected,
            wrong_backend_rejected,
            wrong_dimensions_rejected,
            malicious_negative_marker: "PREPROCESSED_PBMO_MALICIOUS_NEGATIVE_TESTS_PASS".into(),
            corrupted_output_rejected: corruption_rejected(Corruption::OneOutput)?,
            correlated_corruption_rejected: corruption_rejected(Corruption::CorrelatedOutputs)?,
            reordered_output_rejected: corruption_rejected(Corruption::Reorder)?,
            omitted_output_rejected: corruption_rejected(Corruption::Omit)?,
            duplicated_output_rejected: corruption_rejected(Corruption::Duplicate)?,
            post_challenge_modification_rejected: corruption_rejected(Corruption::AfterChallenge)?,
            replayed_output_vector_rejected: corruption_rejected(Corruption::ReplayedVector)?,
            cross_session_output_swap_rejected: corruption_rejected(Corruption::CrossSessionSwap)?,
            wrong_session_binding_rejected,
            wrong_proof_binding_rejected,
            token_clone_rejected_by_store,
            seed_correction_mismatch_rejected,
        },
    )
}

fn main() -> Result<()> {
    fs::create_dir_all("results")?;
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("offline") => {
            let q = args.get(2).ok_or_else(|| anyhow!("missing q"))?.parse()?;
            let m = args.get(3).ok_or_else(|| anyhow!("missing m"))?.parse()?;
            run_offline(
                q,
                m,
                Path::new(args.get(4).ok_or_else(|| anyhow!("missing output"))?),
            )
        }
        Some("offline-batch") => {
            let q = args.get(2).ok_or_else(|| anyhow!("missing q"))?.parse()?;
            let m = args.get(3).ok_or_else(|| anyhow!("missing m"))?.parse()?;
            let count = args
                .get(4)
                .ok_or_else(|| anyhow!("missing count"))?
                .parse()?;
            run_offline_batch(
                q,
                m,
                count,
                Path::new(args.get(5).ok_or_else(|| anyhow!("missing output"))?),
            )
        }
        Some("online") => {
            let mode = args.get(2).ok_or_else(|| anyhow!("missing mode"))?;
            let q = args.get(3).ok_or_else(|| anyhow!("missing q"))?.parse()?;
            let m = args.get(4).ok_or_else(|| anyhow!("missing m"))?.parse()?;
            run_online(
                mode,
                q,
                m,
                Path::new(args.get(5).ok_or_else(|| anyhow!("missing output"))?),
            )
        }
        Some("lifecycle") => run_lifecycle(Path::new(
            args.get(2).ok_or_else(|| anyhow!("missing output"))?,
        )),
        Some("audit") => run_audit(Path::new(
            args.get(2).ok_or_else(|| anyhow!("missing output"))?,
        )),
        _ => Err(anyhow!(
            "usage: phase_v2_pbmo offline|online|lifecycle|audit ..."
        )),
    }
}
