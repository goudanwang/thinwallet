//! Opt-in, protocol-transparent instrumentation for ThinWallet experiments.

use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const SCHEMA_VERSION: &str = "thinwallet-experiment-v1";

const COUNTER_NAMES: &[&str] = &[
    "native_commitment_calls",
    "native_commitment_rows",
    "native_row_msm_calls",
    "native_row_msm_terms",
    "native_row_msm_physical_calls",
    "native_row_msm_physical_terms",
    "native_row_msm_wall_ns",
    "native_row_msm_cpu_ns",
    "pbmo_sessions_started",
    "pbmo_sessions_completed",
    "pbmo_rows_uploaded",
    "pbmo_server_outputs_received",
    "aggregate_checks_executed",
    "aggregate_checks_passed",
    "aggregate_check_msm_calls",
    "aggregate_check_msm_terms",
    "online_correction_msm_calls",
    "online_correction_msm_terms",
    "offline_correction_msm_calls",
    "offline_correction_msm_terms",
    "server_row_msm_calls",
    "server_row_msm_terms",
    "scalar_mask_additions",
    "scalar_aggregate_multiply_adds",
    "serialized_scalar_bytes",
    "spool_bytes_written",
    "spool_bytes_read",
    "token_generation_calls",
    "token_generation_wall_ns",
    "token_generation_cpu_ns",
    "token_generation_msm_calls",
    "token_generation_msm_terms",
    "pregenerated_token_load_calls",
    "pregenerated_token_load_bytes",
    "token_context_validation_calls",
    "token_context_validation_failures",
    "pbmo_token_generation_calls",
    "pbmo_online_correction_msm_calls",
    "pbmo_pregenerated_token_load_calls",
    "pbmo_server_row_msm_calls",
    "pbmo_server_row_msm_terms",
    "spill_files_created",
    "external_fold_rounds",
    "recomputed_objects",
    "phase_fusions",
    "opening_fusions",
    "uses_r1cs_eval_proof",
    "r1cs_sat_calls",
    "r1cs_sat_wall_ns",
    "r1cs_sat_inclusive_wall_ns",
    "r1cs_sat_exclusive_wall_ns",
    "r1cs_sat_cpu_ns",
    "r1cs_sat_inclusive_cpu_ns",
    "r1cs_sat_exclusive_cpu_ns",
    "r1cs_sat_proof_bytes",
    "r1cs_sat_num_cons",
    "r1cs_sat_num_vars",
    "r1cs_sat_num_inputs",
    "q_sat_samples",
    "sat_random_bytes",
    "sat_post_frontier_sample_attempts",
    "sat_frontier_sealed",
    "sat_sample_coordinates_unique",
    "sparse_eval_calls",
    "sparse_eval_wall_ns",
    "sparse_eval_inclusive_wall_ns",
    "sparse_eval_exclusive_wall_ns",
    "sparse_eval_cpu_ns",
    "sparse_eval_inclusive_cpu_ns",
    "sparse_eval_exclusive_cpu_ns",
    "sparse_eval_bytes",
    "sparse_eval_rx_len",
    "sparse_eval_ry_len",
    "r1cs_eval_proof_calls",
    "r1cs_eval_proof_wall_ns",
    "r1cs_eval_proof_inclusive_wall_ns",
    "r1cs_eval_proof_exclusive_wall_ns",
    "r1cs_eval_proof_cpu_ns",
    "r1cs_eval_proof_inclusive_cpu_ns",
    "r1cs_eval_proof_exclusive_cpu_ns",
    "r1cs_eval_proof_bytes",
    "r1cs_eval_rx_len",
    "r1cs_eval_ry_len",
    "r1cs_eval_batch_size",
    "eval_commit_nondet_calls",
    "eval_commit_nondet_wall_ns",
    "eval_commit_nondet_cpu_ns",
    "eval_build_layered_network_calls",
    "eval_build_layered_network_wall_ns",
    "eval_build_layered_network_cpu_ns",
    "eval_layered_proof_calls",
    "eval_layered_proof_wall_ns",
    "eval_layered_proof_cpu_ns",
    "r1cs_eval_verify_calls",
    "r1cs_eval_verify_wall_ns",
    "r1cs_eval_verify_cpu_ns",
    "r1cs_decomm_serialized_bytes",
    "r1cs_decomm_serialization_wall_ns",
    "r1cs_decomm_serialization_cpu_ns",
    "phase_instrumentation_overhead_ns",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstrumentationProfile {
    Off,
    Perf,
    Audit,
}

pub fn profile() -> InstrumentationProfile {
    match std::env::var("THINWALLET_INSTRUMENTATION_PROFILE")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "perf" | "android-perf" => InstrumentationProfile::Perf,
        "audit" => InstrumentationProfile::Audit,
        "off" => InstrumentationProfile::Off,
        _ if std::env::var("THINWALLET_INSTRUMENTATION").as_deref() == Ok("1") => {
            InstrumentationProfile::Audit
        }
        _ => InstrumentationProfile::Off,
    }
}

#[derive(Clone, Default, Serialize)]
pub struct ArtifactRecord {
    pub category: String,
    pub path: String,
    pub created_monotonic_ns: Option<u64>,
    pub removed_monotonic_ns: Option<u64>,
    pub bytes_written_logical: u64,
    pub final_logical_size: u64,
    pub peak_logical_size: u64,
    pub allocated_size_if_available: Option<u64>,
    pub create_count: u64,
    pub write_count: u64,
    pub truncate_count: u64,
    pub remove_count: u64,
}

#[derive(Default)]
struct AuditState {
    run_id: String,
    phase_stack: Vec<String>,
    counters: BTreeMap<String, u64>,
    upload_bytes: u64,
    download_bytes: u64,
    transcript_index: u64,
    transcript_digest: [u8; 32],
    commitment_index: u64,
    commitment_event_count: u64,
    commitment_digest: [u8; 32],
    temp_peak_bytes: u64,
    temp_peak_allocated_bytes: u64,
    temp_peak_file_count: u64,
    temp_latest: Option<TempSnapshot>,
    logical_bytes_written_observed: u64,
    phase_events: Vec<serde_json::Value>,
    artifacts: BTreeMap<String, ArtifactRecord>,
    direct_current_bytes: u64,
    direct_peak_bytes: u64,
    direct_current_allocated_bytes: u64,
    direct_peak_allocated_bytes: u64,
}

#[derive(Clone, Default, Serialize)]
pub struct TempSnapshot {
    pub logical_bytes: u64,
    pub allocated_blocks_bytes: Option<u64>,
    pub file_count: u64,
    pub sumcheck_spill_bytes: u64,
    pub opening_spill_bytes: u64,
    pub pbmo_spool_bytes: u64,
    pub miscellaneous_temp_bytes: u64,
}

static STATE: OnceLock<Mutex<AuditState>> = OnceLock::new();

#[derive(Default)]
struct MeasurementScopeState {
    active: bool,
    name: String,
    verifier_preprocessing_inside_scope: bool,
    verifier_execution_inside_scope: bool,
}

static MEASUREMENT_SCOPE_STATE: OnceLock<Mutex<MeasurementScopeState>> = OnceLock::new();

fn measurement_scope_state() -> &'static Mutex<MeasurementScopeState> {
    MEASUREMENT_SCOPE_STATE.get_or_init(|| Mutex::new(MeasurementScopeState::default()))
}

fn measurement_scope_active() -> bool {
    measurement_scope_state()
        .lock()
        .expect("measurement scope state poisoned")
        .active
}

thread_local! {
    static AUDIT_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

fn state() -> &'static Mutex<AuditState> {
    STATE.get_or_init(|| Mutex::new(AuditState::default()))
}

pub fn enabled() -> bool {
    profile() != InstrumentationProfile::Off
}

pub fn audit_enabled() -> bool {
    profile() == InstrumentationProfile::Audit
}

fn path_from_env(name: &str) -> Option<PathBuf> {
    enabled()
        .then(|| std::env::var_os(name).map(PathBuf::from))
        .flatten()
}

fn append_json(path: &Path, value: &impl Serialize) {
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        if serde_json::to_writer(&mut file, value).is_ok() {
            let _ = file.write_all(b"\n");
            let _ = file.flush();
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn monotonic_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC)
}

/// Returns a local duration clock that includes suspend time on Android.
/// This is only suitable for elapsed-duration subtraction within one process.
pub fn duration_time_ns() -> u64 {
    #[cfg(target_os = "android")]
    {
        clock_ns(libc::CLOCK_BOOTTIME)
    }
    #[cfg(not(target_os = "android"))]
    {
        clock_ns(libc::CLOCK_MONOTONIC_RAW)
    }
}

pub fn duration_clock_name() -> &'static str {
    #[cfg(target_os = "android")]
    {
        "CLOCK_BOOTTIME"
    }
    #[cfg(not(target_os = "android"))]
    {
        "CLOCK_MONOTONIC_RAW"
    }
}

fn process_cpu_ns() -> u64 {
    clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID)
}

pub fn process_cpu_time_ns() -> u64 {
    process_cpu_ns()
}

#[allow(clippy::too_many_arguments)]
pub fn record_native_row_msm_physical_call(
    call_site_id: &str,
    row: usize,
    col_start: usize,
    col_end: usize,
    terms: usize,
    wall_ns: u64,
    cpu_ns: u64,
    q: usize,
    m: usize,
) {
    if !enabled() {
        return;
    }
    {
        let mut guard = state().lock().expect("instrumentation state poisoned");
        for (name, amount) in [
            ("native_row_msm_physical_calls", 1),
            ("native_row_msm_physical_terms", terms as u64),
            ("native_row_msm_wall_ns", wall_ns),
            ("native_row_msm_cpu_ns", cpu_ns),
        ] {
            *guard.counters.entry(name.to_string()).or_default() = guard
                .counters
                .get(name)
                .copied()
                .unwrap_or_default()
                .saturating_add(amount);
        }
    }
    let Some(path) = path_from_env("THINWALLET_NATIVE_ROW_MSM_PATH") else {
        return;
    };
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "event": "native_row_msm_physical_call",
            "mode": std::env::var("THINWALLET_EXPERIMENT_MODE").ok(),
            "call_site_id": call_site_id,
            "row": row,
            "col_start": col_start,
            "col_end": col_end,
            "terms": terms,
            "wall_ns": wall_ns,
            "process_cpu_ns": cpu_ns,
            "thread_id": format!("{:?}", thread::current().id()),
            "workload": std::env::var("THINWALLET_CREDENTIAL_WORKLOAD").ok(),
            "q": q,
            "m": m,
        }),
    );
}

pub fn record_native_row_msm_logical_row(terms: usize) {
    increment_counter("native_row_msm_calls", 1);
    increment_counter("native_row_msm_terms", terms as u64);
}

#[allow(clippy::too_many_arguments)]
pub fn record_stage_metrics(
    stage: &str,
    inclusive_wall_ns: u64,
    exclusive_wall_ns: u64,
    inclusive_cpu_ns: u64,
    exclusive_cpu_ns: u64,
    output_bytes: u64,
) {
    if !enabled() {
        return;
    }
    let overhead_start = monotonic_ns();
    let mut guard = state().lock().expect("instrumentation state poisoned");
    for (suffix, amount) in [
        ("calls", 1),
        ("wall_ns", inclusive_wall_ns),
        ("inclusive_wall_ns", inclusive_wall_ns),
        ("exclusive_wall_ns", exclusive_wall_ns),
        ("cpu_ns", inclusive_cpu_ns),
        ("inclusive_cpu_ns", inclusive_cpu_ns),
        ("exclusive_cpu_ns", exclusive_cpu_ns),
        ("bytes", output_bytes),
    ] {
        let name = format!("{stage}_{suffix}");
        let current = guard.counters.get(&name).copied().unwrap_or_default();
        guard.counters.insert(name, current.saturating_add(amount));
    }
    let overhead = monotonic_ns().saturating_sub(overhead_start);
    let current = guard
        .counters
        .get("phase_instrumentation_overhead_ns")
        .copied()
        .unwrap_or_default();
    guard.counters.insert(
        "phase_instrumentation_overhead_ns".to_string(),
        current.saturating_add(overhead),
    );
}

fn clock_ns(clock: libc::clockid_t) -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let status = unsafe { libc::clock_gettime(clock, &mut value) };
    if status == 0 {
        (value.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(value.tv_nsec as u64)
    } else {
        0
    }
}

fn parse_kib_file(path: &str, names: &[&str]) -> BTreeMap<String, Option<u64>> {
    let mut values = names
        .iter()
        .map(|name| ((*name).to_string(), None))
        .collect::<BTreeMap<_, _>>();
    let Ok(contents) = fs::read_to_string(path) else {
        return values;
    };
    for line in contents.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if let Some(slot) = values.get_mut(name) {
            *slot = rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .map(|kib| kib.saturating_mul(1024));
        }
    }
    values
}

fn memory_reconciliation_enabled() -> bool {
    std::env::var("THINWALLET_MEMORY_RECONCILIATION").as_deref() == Ok("1")
}

fn trim_after_phase_enabled() -> bool {
    memory_reconciliation_enabled()
        && std::env::var("THINWALLET_MALLOC_TRIM_AFTER_PHASE").as_deref() == Ok("1")
}

#[cfg(target_os = "linux")]
fn diagnostic_malloc_trim() -> Option<i32> {
    unsafe extern "C" {
        fn malloc_trim(pad: usize) -> i32;
    }
    Some(unsafe { malloc_trim(0) })
}

#[cfg(not(target_os = "linux"))]
fn diagnostic_malloc_trim() -> Option<i32> {
    None
}

#[derive(Clone, Default, Serialize)]
struct MappedFileRecord {
    path: String,
    mapping_virtual_bytes: u64,
    rss_bytes: u64,
    pss_bytes: u64,
    private_dirty_bytes: u64,
    shared_clean_bytes: u64,
    resident_page_count: u64,
    is_experiment_temp: bool,
}

fn mapped_file_records() -> Vec<MappedFileRecord> {
    let Ok(contents) = fs::read_to_string("/proc/self/smaps") else {
        return Vec::new();
    };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }
        .try_into()
        .ok()
        .filter(|value: &u64| *value > 0)
        .unwrap_or(4096);
    let temp_root = std::env::var("THINWALLET_EXPERIMENT_TEMP_DIR").ok();
    let mut records = BTreeMap::<String, MappedFileRecord>::new();
    let mut current_path: Option<String> = None;

    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let address = fields.next().unwrap_or_default();
        let permissions = fields.next().unwrap_or_default();
        let is_header = address.split_once('-').is_some_and(|(start, end)| {
            !start.is_empty()
                && !end.is_empty()
                && start.chars().all(|value| value.is_ascii_hexdigit())
                && end.chars().all(|value| value.is_ascii_hexdigit())
        }) && permissions.len() == 4;
        if is_header {
            let path = line
                .split_whitespace()
                .skip(5)
                .collect::<Vec<_>>()
                .join(" ");
            current_path =
                (path.starts_with('/') || path.starts_with('[') || path.contains("(deleted)"))
                    .then_some(path);
            if let Some(path) = current_path.as_ref() {
                records
                    .entry(path.clone())
                    .or_insert_with(|| MappedFileRecord {
                        path: path.clone(),
                        is_experiment_temp: temp_root
                            .as_ref()
                            .is_some_and(|root| path.starts_with(root)),
                        ..MappedFileRecord::default()
                    });
            }
            continue;
        }
        let Some(path) = current_path.as_ref() else {
            continue;
        };
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(bytes) = rest
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .map(|kib| kib.saturating_mul(1024))
        else {
            continue;
        };
        let record = records.get_mut(path).expect("mapped-file record missing");
        match name {
            "Size" => {
                record.mapping_virtual_bytes = record.mapping_virtual_bytes.saturating_add(bytes);
            }
            "Rss" => record.rss_bytes = record.rss_bytes.saturating_add(bytes),
            "Pss" => record.pss_bytes = record.pss_bytes.saturating_add(bytes),
            "Private_Dirty" => {
                record.private_dirty_bytes = record.private_dirty_bytes.saturating_add(bytes);
            }
            "Shared_Clean" => {
                record.shared_clean_bytes = record.shared_clean_bytes.saturating_add(bytes);
            }
            _ => {}
        }
    }
    let mut values = records.into_values().collect::<Vec<_>>();
    for record in &mut values {
        record.resident_page_count = record.rss_bytes.div_ceil(page_size);
    }
    values.sort_by(|left, right| {
        right
            .rss_bytes
            .cmp(&left.rss_bytes)
            .then_with(|| left.path.cmp(&right.path))
    });
    values
}

fn record_mapped_files(phase: &str, event: &str, timestamp_monotonic_ns: u64) {
    if !memory_reconciliation_enabled() {
        return;
    }
    let Some(path) = path_from_env("THINWALLET_MEMORY_MAPS_PATH") else {
        return;
    };
    let mappings = mapped_file_records();
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "phase": phase,
            "event": event,
            "timestamp_monotonic_ns": timestamp_monotonic_ns,
            "mapped_files": mappings,
        }),
    );
}

fn io_values() -> BTreeMap<String, Option<u64>> {
    let names = ["read_bytes", "write_bytes", "rchar", "wchar"];
    let mut values = names
        .iter()
        .map(|name| ((*name).to_string(), None))
        .collect::<BTreeMap<_, _>>();
    let Ok(contents) = fs::read_to_string("/proc/self/io") else {
        return values;
    };
    for line in contents.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if let Some(slot) = values.get_mut(name) {
            *slot = rest.trim().parse().ok();
        }
    }
    values
}

#[cfg(unix)]
fn allocated_bytes(metadata: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.blocks().saturating_mul(512))
}

#[cfg(not(unix))]
fn allocated_bytes(_metadata: &fs::Metadata) -> Option<u64> {
    None
}

fn scan_temp_dir(root: &Path) -> TempSnapshot {
    fn visit(root: &Path, current: &Path, snapshot: &mut TempSnapshot) {
        let Ok(entries) = fs::read_dir(current) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                visit(root, &path, snapshot);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let bytes = metadata.len();
            snapshot.logical_bytes = snapshot.logical_bytes.saturating_add(bytes);
            snapshot.file_count = snapshot.file_count.saturating_add(1);
            snapshot.allocated_blocks_bytes =
                match (snapshot.allocated_blocks_bytes, allocated_bytes(&metadata)) {
                    (Some(total), Some(value)) => Some(total.saturating_add(value)),
                    (None, Some(value)) => Some(value),
                    _ => None,
                };
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_ascii_lowercase();
            if relative.contains("sumcheck") || relative.contains("prover-state") {
                snapshot.sumcheck_spill_bytes = snapshot.sumcheck_spill_bytes.saturating_add(bytes);
            } else if relative.contains("opening") || relative.contains("dereference") {
                snapshot.opening_spill_bytes = snapshot.opening_spill_bytes.saturating_add(bytes);
            } else if relative.contains("pbmo") || relative.ends_with(".spool") {
                snapshot.pbmo_spool_bytes = snapshot.pbmo_spool_bytes.saturating_add(bytes);
            } else {
                snapshot.miscellaneous_temp_bytes =
                    snapshot.miscellaneous_temp_bytes.saturating_add(bytes);
            }
        }
    }

    let mut snapshot = TempSnapshot {
        allocated_blocks_bytes: Some(0),
        ..TempSnapshot::default()
    };
    visit(root, root, &mut snapshot);
    snapshot
}

pub fn initialize() {
    if !enabled() && std::env::var("THINWALLET_REQUIRE_PREGENERATED_TOKEN").as_deref() != Ok("1") {
        return;
    }
    let run_id = std::env::var("THINWALLET_EXPERIMENT_RUN_ID").unwrap_or_default();
    let mut guard = state().lock().expect("instrumentation state poisoned");
    *guard = AuditState {
        run_id,
        counters: COUNTER_NAMES
            .iter()
            .map(|name| ((*name).to_string(), 0))
            .collect(),
        ..AuditState::default()
    };
    drop(guard);
    for name in [
        "THINWALLET_PHASES_PATH",
        "THINWALLET_TRANSCRIPT_AUDIT_PATH",
        "THINWALLET_COMMITMENTS_AUDIT_PATH",
        "THINWALLET_COUNTERS_PATH",
        "THINWALLET_NATIVE_ROW_MSM_PATH",
        "THINWALLET_TEMP_ARTIFACTS_PATH",
        "THINWALLET_MEMORY_MAPS_PATH",
    ] {
        if let Some(path) = path_from_env(name) {
            let _ = fs::remove_file(path);
        }
    }
    if audit_enabled() {
        observe_temp_storage();
    }
}

pub fn increment_counter(name: &str, amount: u64) {
    if !enabled() && std::env::var("THINWALLET_REQUIRE_PREGENERATED_TOKEN").as_deref() != Ok("1") {
        return;
    }
    let mut guard = state().lock().expect("instrumentation state poisoned");
    *guard.counters.entry(name.to_string()).or_default() = guard
        .counters
        .get(name)
        .copied()
        .unwrap_or_default()
        .saturating_add(amount);
}

pub fn counters_snapshot() -> BTreeMap<String, u64> {
    if !enabled() && std::env::var("THINWALLET_REQUIRE_PREGENERATED_TOKEN").as_deref() != Ok("1") {
        return COUNTER_NAMES
            .iter()
            .map(|name| ((*name).to_string(), 0))
            .collect();
    }
    state()
        .lock()
        .expect("instrumentation state poisoned")
        .counters
        .clone()
}

pub fn flush_counters() {
    flush_phase_events();
    flush_temp_artifacts();
    let Some(path) = path_from_env("THINWALLET_COUNTERS_PATH") else {
        return;
    };
    let counters = counters_snapshot();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(
        path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": SCHEMA_VERSION,
            "execution_counters": counters,
        }))
        .unwrap(),
    );
}

pub fn add_network_bytes(upload: u64, download: u64) {
    if !enabled() {
        return;
    }
    let mut guard = state().lock().expect("instrumentation state poisoned");
    guard.upload_bytes = guard.upload_bytes.saturating_add(upload);
    guard.download_bytes = guard.download_bytes.saturating_add(download);
}

pub fn record_temp_write(bytes: u64) {
    if !enabled() {
        return;
    }
    let mut guard = state().lock().expect("instrumentation state poisoned");
    guard.logical_bytes_written_observed =
        guard.logical_bytes_written_observed.saturating_add(bytes);
    drop(guard);
    if audit_enabled() {
        observe_temp_storage();
    }
}

fn artifact_key(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn refresh_artifact(record: &mut ArtifactRecord, path: &Path) {
    if let Ok(metadata) = fs::metadata(path) {
        record.final_logical_size = metadata.len();
        record.peak_logical_size = record.peak_logical_size.max(metadata.len());
        record.allocated_size_if_available = allocated_bytes(&metadata);
    }
}

pub fn register_temp_artifact(path: &Path, category: &str) {
    if !enabled() {
        return;
    }
    let key = artifact_key(path);
    let mut guard = state().lock().expect("instrumentation state poisoned");
    let (old_size, new_size, old_allocated, new_allocated) = {
        let record = guard
            .artifacts
            .entry(key.clone())
            .or_insert_with(|| ArtifactRecord {
                category: category.to_string(),
                path: key,
                ..ArtifactRecord::default()
            });
        let old_size = record.final_logical_size;
        let old_allocated = record.allocated_size_if_available.unwrap_or_default();
        record.category = category.to_string();
        record.created_monotonic_ns.get_or_insert_with(monotonic_ns);
        record.create_count = record.create_count.saturating_add(1);
        refresh_artifact(record, path);
        (
            old_size,
            record.final_logical_size,
            old_allocated,
            record.allocated_size_if_available.unwrap_or_default(),
        )
    };
    guard.direct_current_bytes = guard
        .direct_current_bytes
        .saturating_sub(old_size)
        .saturating_add(new_size);
    guard.direct_peak_bytes = guard.direct_peak_bytes.max(guard.direct_current_bytes);
    guard.direct_current_allocated_bytes = guard
        .direct_current_allocated_bytes
        .saturating_sub(old_allocated)
        .saturating_add(new_allocated);
    guard.direct_peak_allocated_bytes = guard
        .direct_peak_allocated_bytes
        .max(guard.direct_current_allocated_bytes);
}

pub fn record_artifact_write(path: &Path, bytes: u64) {
    if !enabled() {
        return;
    }
    let key = artifact_key(path);
    let mut guard = state().lock().expect("instrumentation state poisoned");
    let (old_size, new_size, old_allocated, new_allocated) = {
        let record = guard
            .artifacts
            .entry(key.clone())
            .or_insert_with(|| ArtifactRecord {
                category: "miscellaneous".to_string(),
                path: key,
                created_monotonic_ns: Some(monotonic_ns()),
                ..ArtifactRecord::default()
            });
        let old_size = record.final_logical_size;
        let old_allocated = record.allocated_size_if_available.unwrap_or_default();
        record.bytes_written_logical = record.bytes_written_logical.saturating_add(bytes);
        record.write_count = record.write_count.saturating_add(1);
        refresh_artifact(record, path);
        (
            old_size,
            record.final_logical_size,
            old_allocated,
            record.allocated_size_if_available.unwrap_or_default(),
        )
    };
    guard.direct_current_bytes = guard
        .direct_current_bytes
        .saturating_sub(old_size)
        .saturating_add(new_size);
    guard.direct_peak_bytes = guard.direct_peak_bytes.max(guard.direct_current_bytes);
    guard.direct_current_allocated_bytes = guard
        .direct_current_allocated_bytes
        .saturating_sub(old_allocated)
        .saturating_add(new_allocated);
    guard.direct_peak_allocated_bytes = guard
        .direct_peak_allocated_bytes
        .max(guard.direct_current_allocated_bytes);
    guard.logical_bytes_written_observed =
        guard.logical_bytes_written_observed.saturating_add(bytes);
}

pub fn record_artifact_truncate(path: &Path) {
    if !enabled() {
        return;
    }
    let key = artifact_key(path);
    let mut guard = state().lock().expect("instrumentation state poisoned");
    let (old_size, new_size, old_allocated, new_allocated) = {
        let record = guard
            .artifacts
            .entry(key.clone())
            .or_insert_with(|| ArtifactRecord {
                category: "miscellaneous".to_string(),
                path: key,
                created_monotonic_ns: Some(monotonic_ns()),
                ..ArtifactRecord::default()
            });
        let old_size = record.final_logical_size;
        let old_allocated = record.allocated_size_if_available.unwrap_or_default();
        record.truncate_count = record.truncate_count.saturating_add(1);
        refresh_artifact(record, path);
        (
            old_size,
            record.final_logical_size,
            old_allocated,
            record.allocated_size_if_available.unwrap_or_default(),
        )
    };
    guard.direct_current_bytes = guard
        .direct_current_bytes
        .saturating_sub(old_size)
        .saturating_add(new_size);
    guard.direct_current_allocated_bytes = guard
        .direct_current_allocated_bytes
        .saturating_sub(old_allocated)
        .saturating_add(new_allocated);
}

pub fn record_artifact_remove(path: &Path) {
    if !enabled() {
        return;
    }
    let key = artifact_key(path);
    let mut guard = state().lock().expect("instrumentation state poisoned");
    let (old_size, old_allocated) = {
        let record = guard
            .artifacts
            .entry(key.clone())
            .or_insert_with(|| ArtifactRecord {
                category: "miscellaneous".to_string(),
                path: key,
                created_monotonic_ns: Some(monotonic_ns()),
                ..ArtifactRecord::default()
            });
        refresh_artifact(record, path);
        let old_size = record.final_logical_size;
        let old_allocated = record.allocated_size_if_available.unwrap_or_default();
        record.final_logical_size = 0;
        record.removed_monotonic_ns = Some(monotonic_ns());
        record.remove_count = record.remove_count.saturating_add(1);
        (old_size, old_allocated)
    };
    guard.direct_current_bytes = guard.direct_current_bytes.saturating_sub(old_size);
    guard.direct_current_allocated_bytes = guard
        .direct_current_allocated_bytes
        .saturating_sub(old_allocated);
}

pub fn flush_temp_artifacts() {
    let Some(path) = path_from_env("THINWALLET_TEMP_ARTIFACTS_PATH") else {
        return;
    };
    let artifacts = state()
        .lock()
        .expect("instrumentation state poisoned")
        .artifacts
        .values()
        .cloned()
        .collect::<Vec<_>>();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(
        path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": SCHEMA_VERSION,
            "artifacts": artifacts,
        }))
        .unwrap(),
    );
}

pub fn observe_temp_storage() {
    let Some(root) = path_from_env("THINWALLET_EXPERIMENT_TEMP_DIR") else {
        return;
    };
    let snapshot = scan_temp_dir(&root);
    let mut guard = state().lock().expect("instrumentation state poisoned");
    guard.temp_peak_bytes = guard.temp_peak_bytes.max(snapshot.logical_bytes);
    if let Some(allocated) = snapshot.allocated_blocks_bytes {
        guard.temp_peak_allocated_bytes = guard.temp_peak_allocated_bytes.max(allocated);
    }
    guard.temp_peak_file_count = guard.temp_peak_file_count.max(snapshot.file_count);
    guard.temp_latest = Some(snapshot);
}

pub fn temp_storage_report(cleanup_success: Option<bool>) -> serde_json::Value {
    if audit_enabled() {
        observe_temp_storage();
    }
    let guard = state().lock().expect("instrumentation state poisoned");
    let latest = guard.temp_latest.clone().unwrap_or_default();
    let direct_peak = guard.direct_peak_bytes;
    let direct_final = guard.direct_current_bytes;
    let direct_allocated = guard.direct_current_allocated_bytes;
    json!({
        "schema_version": SCHEMA_VERSION,
        "temp_peak_bytes": guard.temp_peak_bytes.max(direct_peak),
        "temp_final_bytes": latest.logical_bytes.max(direct_final),
        "logical_bytes_written": guard.logical_bytes_written_observed,
        "logical_bytes_written_observed": guard.logical_bytes_written_observed,
        "logical_bytes_written_status": "direct_registered_artifact_accounting",
        "allocated_blocks_bytes": latest.allocated_blocks_bytes.or(Some(direct_allocated)),
        "temp_peak_allocated_blocks_bytes": guard.temp_peak_allocated_bytes.max(guard.direct_peak_allocated_bytes),
        "spill_file_count": latest.file_count,
        "temp_peak_file_count": guard.temp_peak_file_count.max(guard.artifacts.len() as u64),
        "cleanup_success": cleanup_success,
        "sumcheck_spill_bytes": latest.sumcheck_spill_bytes,
        "opening_spill_bytes": latest.opening_spill_bytes,
        "pbmo_spool_bytes": latest.pbmo_spool_bytes,
        "miscellaneous_temp_bytes": latest.miscellaneous_temp_bytes,
    })
}

#[derive(Clone)]
struct ProcessSnapshot {
    rss_bytes: Option<u64>,
    vmhwm_bytes: Option<u64>,
    pss_bytes: Option<u64>,
    pss_anon_bytes: Option<u64>,
    pss_file_bytes: Option<u64>,
    private_dirty_bytes: Option<u64>,
    shared_clean_bytes: Option<u64>,
    read_bytes: Option<u64>,
    write_bytes: Option<u64>,
    temp_storage_bytes: u64,
}

fn process_snapshot() -> ProcessSnapshot {
    if audit_enabled() {
        observe_temp_storage();
    }
    let status = parse_kib_file("/proc/self/status", &["VmRSS", "VmHWM"]);
    let smaps = if audit_enabled()
        || memory_reconciliation_enabled()
        || (enabled() && measurement_scope_active())
    {
        parse_kib_file(
            "/proc/self/smaps_rollup",
            &[
                "Pss",
                "Pss_Anon",
                "Pss_File",
                "Private_Dirty",
                "Shared_Clean",
            ],
        )
    } else {
        [
            "Pss",
            "Pss_Anon",
            "Pss_File",
            "Private_Dirty",
            "Shared_Clean",
        ]
        .into_iter()
        .map(|name| (name.to_string(), None))
        .collect()
    };
    let io = io_values();
    let temp_storage_bytes = state()
        .lock()
        .expect("instrumentation state poisoned")
        .temp_latest
        .as_ref()
        .map(|value| value.logical_bytes)
        .unwrap_or_default();
    ProcessSnapshot {
        rss_bytes: status.get("VmRSS").copied().flatten(),
        vmhwm_bytes: status.get("VmHWM").copied().flatten(),
        pss_bytes: smaps.get("Pss").copied().flatten(),
        pss_anon_bytes: smaps.get("Pss_Anon").copied().flatten(),
        pss_file_bytes: smaps.get("Pss_File").copied().flatten(),
        private_dirty_bytes: smaps.get("Private_Dirty").copied().flatten(),
        shared_clean_bytes: smaps.get("Shared_Clean").copied().flatten(),
        read_bytes: io.get("read_bytes").copied().flatten(),
        write_bytes: io.get("write_bytes").copied().flatten(),
        temp_storage_bytes,
    }
}

fn process_snapshot_json(snapshot: &ProcessSnapshot) -> serde_json::Value {
    json!({
        "rss_bytes": snapshot.rss_bytes,
        "vmhwm_bytes": snapshot.vmhwm_bytes,
        "pss_bytes": snapshot.pss_bytes,
        "pss_anon_bytes": snapshot.pss_anon_bytes,
        "pss_file_bytes": snapshot.pss_file_bytes,
        "private_dirty_bytes": snapshot.private_dirty_bytes,
        "shared_clean_bytes": snapshot.shared_clean_bytes,
        "read_bytes": snapshot.read_bytes,
        "write_bytes": snapshot.write_bytes,
        "temp_storage_bytes": snapshot.temp_storage_bytes,
    })
}

#[derive(Clone, Serialize)]
pub struct MeasurementScopeReport {
    pub measurement_scope: String,
    pub started_monotonic_ns: u64,
    pub ended_monotonic_ns: u64,
    pub started_process_cpu_ns: u64,
    pub ended_process_cpu_ns: u64,
    pub baseline_before_scope: serde_json::Value,
    pub final_scope_sample: serde_json::Value,
    pub verifier_preprocessing_inside_measured_scope: bool,
    pub verifier_execution_inside_measured_scope: bool,
    pub valid_measurement_scope: bool,
}

pub struct MeasurementScopeGuard {
    name: String,
    started_monotonic_ns: u64,
    started_process_cpu_ns: u64,
    baseline: ProcessSnapshot,
    sampler: Option<SamplerGuard>,
    finished: bool,
}

impl MeasurementScopeGuard {
    pub fn finish(mut self) -> MeasurementScopeReport {
        if let Some(sampler) = self.sampler.take() {
            drop(sampler);
        }
        let final_snapshot = process_snapshot();
        let ended_monotonic_ns = monotonic_ns();
        let ended_process_cpu_ns = process_cpu_ns();
        let (verifier_preprocessing, verifier_execution) = {
            let mut guard = measurement_scope_state()
                .lock()
                .expect("measurement scope state poisoned");
            let values = (
                guard.verifier_preprocessing_inside_scope,
                guard.verifier_execution_inside_scope,
            );
            guard.active = false;
            values
        };
        self.finished = true;
        MeasurementScopeReport {
            measurement_scope: self.name.clone(),
            started_monotonic_ns: self.started_monotonic_ns,
            ended_monotonic_ns,
            started_process_cpu_ns: self.started_process_cpu_ns,
            ended_process_cpu_ns,
            baseline_before_scope: process_snapshot_json(&self.baseline),
            final_scope_sample: process_snapshot_json(&final_snapshot),
            verifier_preprocessing_inside_measured_scope: verifier_preprocessing,
            verifier_execution_inside_measured_scope: verifier_execution,
            valid_measurement_scope: !verifier_preprocessing && !verifier_execution,
        }
    }
}

impl Drop for MeasurementScopeGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Some(sampler) = self.sampler.take() {
            drop(sampler);
        }
        measurement_scope_state()
            .lock()
            .expect("measurement scope state poisoned")
            .active = false;
    }
}

pub fn begin_measurement_scope(
    name: &str,
    sample_ms: u64,
) -> Result<MeasurementScopeGuard, String> {
    {
        let mut guard = measurement_scope_state()
            .lock()
            .expect("measurement scope state poisoned");
        if guard.active {
            return Err("nested measurement scope".to_string());
        }
        guard.active = true;
        guard.name = name.to_string();
        guard.verifier_preprocessing_inside_scope = false;
        guard.verifier_execution_inside_scope = false;
    }
    let started_monotonic_ns = monotonic_ns();
    let started_process_cpu_ns = process_cpu_ns();
    let baseline = process_snapshot();
    let sampler = start_sampler(sample_ms);
    if enabled() && sampler.is_none() {
        measurement_scope_state()
            .lock()
            .expect("measurement scope state poisoned")
            .active = false;
        return Err("instrumentation enabled but prover-scope sampler could not start".to_string());
    }
    Ok(MeasurementScopeGuard {
        name: name.to_string(),
        started_monotonic_ns,
        started_process_cpu_ns,
        baseline,
        sampler,
        finished: false,
    })
}

pub fn mark_verifier_preprocessing() {
    let mut guard = measurement_scope_state()
        .lock()
        .expect("measurement scope state poisoned");
    if guard.active {
        guard.verifier_preprocessing_inside_scope = true;
    }
}

fn mark_verifier_execution() {
    let mut guard = measurement_scope_state()
        .lock()
        .expect("measurement scope state poisoned");
    if guard.active {
        guard.verifier_execution_inside_scope = true;
    }
}

pub struct PhaseGuard {
    phase: String,
    started_ns: u64,
    finished: bool,
}

impl PhaseGuard {
    pub fn begin(phase: &str) -> Self {
        if phase == "verification" {
            mark_verifier_execution();
        }
        let hot_loop_phase = matches!(
            phase,
            "pbmo_mask_generation" | "pbmo_request_spool" | "pbmo_upload"
        );
        if !enabled() || (profile() == InstrumentationProfile::Perf && hot_loop_phase) {
            return Self {
                phase: phase.to_string(),
                started_ns: 0,
                finished: true,
            };
        }
        let timestamp = monotonic_ns();
        let (run_id, stack, upload, download) = {
            let mut guard = state().lock().expect("instrumentation state poisoned");
            guard.phase_stack.push(phase.to_string());
            (
                guard.run_id.clone(),
                guard.phase_stack.clone(),
                guard.upload_bytes,
                guard.download_bytes,
            )
        };
        let snapshot = process_snapshot();
        record_mapped_files(phase, "begin", timestamp);
        let event = json!({
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "event": "begin",
            "phase": phase,
            "status": "running",
            "timestamp_monotonic_ns": timestamp,
            "elapsed_ns_on_end": null,
            "process_cpu_ns": process_cpu_ns(),
            "rss_bytes": snapshot.rss_bytes,
            "vmhwm_bytes": snapshot.vmhwm_bytes,
            "pss_bytes_or_null": snapshot.pss_bytes,
            "pss_anon_bytes_or_null": snapshot.pss_anon_bytes,
            "pss_file_bytes_or_null": snapshot.pss_file_bytes,
            "private_dirty_bytes_or_null": snapshot.private_dirty_bytes,
            "shared_clean_bytes_or_null": snapshot.shared_clean_bytes,
            "temp_storage_bytes": snapshot.temp_storage_bytes,
            "read_bytes_or_null": snapshot.read_bytes,
            "write_bytes_or_null": snapshot.write_bytes,
            "upload_bytes": upload,
            "download_bytes": download,
            "active_phase": stack.last(),
            "phase_stack": stack,
            "error_class_or_null": null,
        });
        if profile() == InstrumentationProfile::Perf {
            state()
                .lock()
                .expect("instrumentation state poisoned")
                .phase_events
                .push(event);
        } else if let Some(path) = path_from_env("THINWALLET_PHASES_PATH") {
            append_json(&path, &event);
        }
        Self {
            phase: phase.to_string(),
            started_ns: timestamp,
            finished: false,
        }
    }

    pub fn finish_error(mut self, error_class: &str) {
        self.finish("error", Some(error_class));
    }

    fn finish(&mut self, status: &str, error: Option<&str>) {
        if self.finished {
            return;
        }
        let timestamp = monotonic_ns();
        let (run_id, stack, upload, download) = {
            let mut guard = state().lock().expect("instrumentation state poisoned");
            if guard.phase_stack.last() == Some(&self.phase) {
                guard.phase_stack.pop();
            } else if let Some(index) = guard
                .phase_stack
                .iter()
                .rposition(|value| value == &self.phase)
            {
                guard.phase_stack.remove(index);
            }
            (
                guard.run_id.clone(),
                guard.phase_stack.clone(),
                guard.upload_bytes,
                guard.download_bytes,
            )
        };
        let snapshot = process_snapshot();
        record_mapped_files(&self.phase, "end_pre_trim", timestamp);
        let trim_result = trim_after_phase_enabled()
            .then(diagnostic_malloc_trim)
            .flatten();
        let post_trim_snapshot = trim_result.map(|_| process_snapshot());
        if post_trim_snapshot.is_some() {
            record_mapped_files(&self.phase, "end_post_trim", monotonic_ns());
        }
        let event = json!({
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "event": "end",
            "phase": self.phase,
            "status": status,
            "timestamp_monotonic_ns": timestamp,
            "elapsed_ns_on_end": timestamp.saturating_sub(self.started_ns),
            "process_cpu_ns": process_cpu_ns(),
            "rss_bytes": snapshot.rss_bytes,
            "vmhwm_bytes": snapshot.vmhwm_bytes,
            "pss_bytes_or_null": snapshot.pss_bytes,
            "pss_anon_bytes_or_null": snapshot.pss_anon_bytes,
            "pss_file_bytes_or_null": snapshot.pss_file_bytes,
            "private_dirty_bytes_or_null": snapshot.private_dirty_bytes,
            "shared_clean_bytes_or_null": snapshot.shared_clean_bytes,
            "malloc_trim_result_or_null": trim_result,
            "post_trim_rss_bytes_or_null": post_trim_snapshot.as_ref().and_then(|value| value.rss_bytes),
            "post_trim_pss_bytes_or_null": post_trim_snapshot.as_ref().and_then(|value| value.pss_bytes),
            "post_trim_pss_anon_bytes_or_null": post_trim_snapshot.as_ref().and_then(|value| value.pss_anon_bytes),
            "post_trim_pss_file_bytes_or_null": post_trim_snapshot.as_ref().and_then(|value| value.pss_file_bytes),
            "temp_storage_bytes": snapshot.temp_storage_bytes,
            "read_bytes_or_null": snapshot.read_bytes,
            "write_bytes_or_null": snapshot.write_bytes,
            "upload_bytes": upload,
            "download_bytes": download,
            "active_phase": stack.last(),
            "phase_stack": stack,
            "error_class_or_null": error,
        });
        if profile() == InstrumentationProfile::Perf {
            state()
                .lock()
                .expect("instrumentation state poisoned")
                .phase_events
                .push(event);
        } else if let Some(path) = path_from_env("THINWALLET_PHASES_PATH") {
            append_json(&path, &event);
        }
        self.finished = true;
    }
}

pub fn flush_phase_events() {
    let Some(path) = path_from_env("THINWALLET_PHASES_PATH") else {
        return;
    };
    let mut events = {
        let mut guard = state().lock().expect("instrumentation state poisoned");
        std::mem::take(&mut guard.phase_events)
    };
    events.sort_by_key(|event| {
        event
            .get("timestamp_monotonic_ns")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default()
    });
    for event in events {
        append_json(&path, &event);
    }
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        if !self.finished {
            if thread::panicking() {
                self.finish("error", Some("panic"));
            } else {
                self.finish("success", None);
            }
        }
    }
}

pub struct ProverAuditGuard {
    previous: bool,
}

pub fn begin_prover_audit() -> ProverAuditGuard {
    if audit_enabled() {
        let mut guard = state().lock().expect("instrumentation state poisoned");
        guard.transcript_index = 0;
        guard.transcript_digest = [0u8; 32];
        guard.commitment_index = 0;
        guard.commitment_event_count = 0;
        guard.commitment_digest = [0u8; 32];
        drop(guard);
        for name in [
            "THINWALLET_TRANSCRIPT_AUDIT_PATH",
            "THINWALLET_COMMITMENTS_AUDIT_PATH",
        ] {
            if let Some(path) = path_from_env(name) {
                let _ = fs::remove_file(path);
            }
        }
    }
    let previous = AUDIT_ACTIVE.with(|active| active.replace(true));
    ProverAuditGuard { previous }
}

impl Drop for ProverAuditGuard {
    fn drop(&mut self) {
        AUDIT_ACTIVE.with(|active| active.set(self.previous));
    }
}

fn audit_active() -> bool {
    audit_enabled() && AUDIT_ACTIVE.with(Cell::get)
}

pub fn record_transcript_event(operation: &str, label: &[u8], input: Option<&[u8]>) {
    if !audit_active() {
        return;
    }
    let input = input.unwrap_or_default();
    let label_hash = sha256(label);
    let input_hash = sha256(input);
    let (event_index, state_digest) = {
        let mut guard = state().lock().expect("instrumentation state poisoned");
        let index = guard.transcript_index;
        let mut hasher = Sha256::new();
        hasher.update(b"thinwallet/transcript-audit-event/v1");
        hasher.update(guard.transcript_digest);
        hasher.update(index.to_be_bytes());
        hasher.update((operation.len() as u64).to_be_bytes());
        hasher.update(operation.as_bytes());
        hasher.update((label.len() as u64).to_be_bytes());
        hasher.update(label);
        hasher.update((input.len() as u64).to_be_bytes());
        hasher.update(input);
        guard.transcript_digest = hasher.finalize().into();
        guard.transcript_index += 1;
        (index, sha256(&guard.transcript_digest))
    };
    if let Some(path) = path_from_env("THINWALLET_TRANSCRIPT_AUDIT_PATH") {
        append_json(
            &path,
            &json!({
                "event_index": event_index,
                "operation_type": operation,
                "domain_label_hash": label_hash,
                "input_length": input.len(),
                "input_sha256": input_hash,
                "transcript_state_digest_after_event": state_digest,
                "state_digest_semantics": "ordered-event-stream digest; not Merlin internal sponge state",
            }),
        );
    }
}

pub fn next_commitment_call_id() -> u64 {
    if !audit_enabled() {
        return 0;
    }
    let mut guard = state().lock().expect("instrumentation state poisoned");
    let id = guard.commitment_index;
    guard.commitment_index += 1;
    id
}

pub fn record_commitment(
    logical_call_id: u64,
    output_index: usize,
    output_count: usize,
    point_encoding: &[u8],
    blinded: bool,
) {
    if !audit_active() {
        return;
    }
    if !audit_active() {
        return;
    }
    let point_hash = sha256(point_encoding);
    {
        let mut guard = state().lock().expect("instrumentation state poisoned");
        let mut hasher = Sha256::new();
        hasher.update(b"thinwallet/commitment-audit-event/v1");
        hasher.update(guard.commitment_digest);
        hasher.update(logical_call_id.to_be_bytes());
        hasher.update((output_index as u64).to_be_bytes());
        hasher.update((output_count as u64).to_be_bytes());
        hasher.update([u8::from(blinded)]);
        hasher.update((point_encoding.len() as u64).to_be_bytes());
        hasher.update(point_encoding);
        guard.commitment_digest = hasher.finalize().into();
        guard.commitment_event_count = guard.commitment_event_count.saturating_add(1);
    }
    if let Some(path) = path_from_env("THINWALLET_COMMITMENTS_AUDIT_PATH") {
        append_json(
            &path,
            &json!({
                "logical_commitment_call_id": logical_call_id,
                "output_index": output_index,
                "output_count": output_count,
                "point_encoding_length": point_encoding.len(),
                "point_sha256": point_hash,
                "blinded_or_unblinded": if blinded { "blinded" } else { "unblinded" },
            }),
        );
    }
}

pub fn audit_digests() -> serde_json::Value {
    let guard = state().lock().expect("instrumentation state poisoned");
    json!({
        "transcript_event_count": guard.transcript_index,
        "transcript_audit_sha256": sha256(&guard.transcript_digest),
        "logical_commitment_call_count": guard.commitment_index,
        "ordered_commitment_count": guard.commitment_event_count,
        "ordered_commitments_sha256": sha256(&guard.commitment_digest),
    })
}

fn csv_value(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_string(), |value| value.to_string())
}

fn csv_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn sample(memory: &mut File, io_file: &mut File) -> io::Result<()> {
    if audit_enabled() {
        observe_temp_storage();
    }
    let timestamp = monotonic_ns();
    let (active, stack) = {
        let guard = state().lock().expect("instrumentation state poisoned");
        (
            guard.phase_stack.last().cloned().unwrap_or_default(),
            guard.phase_stack.clone(),
        )
    };
    let status = parse_kib_file(
        "/proc/self/status",
        &["VmRSS", "VmHWM", "VmSize", "RssAnon", "RssFile", "RssShmem"],
    );
    let smaps = parse_kib_file(
        "/proc/self/smaps_rollup",
        &[
            "Pss",
            "Pss_Anon",
            "Pss_File",
            "Private_Clean",
            "Private_Dirty",
            "Shared_Clean",
            "Shared_Dirty",
        ],
    );
    let io = io_values();
    let stack_json = serde_json::to_string(&stack).unwrap();
    let memory_row = [
        timestamp.to_string(),
        csv_quote(&active),
        csv_quote(&stack_json),
        csv_value(status["VmRSS"]),
        csv_value(status["VmHWM"]),
        csv_value(status["VmSize"]),
        csv_value(status["RssAnon"]),
        csv_value(status["RssFile"]),
        csv_value(status["RssShmem"]),
        csv_value(smaps["Pss"]),
        csv_value(smaps["Pss_Anon"]),
        csv_value(smaps["Pss_File"]),
        csv_value(smaps["Private_Clean"]),
        csv_value(smaps["Private_Dirty"]),
        csv_value(smaps["Shared_Clean"]),
        csv_value(smaps["Shared_Dirty"]),
        process_cpu_ns().to_string(),
    ];
    writeln!(memory, "{}", memory_row.join(","))?;
    writeln!(
        io_file,
        "{timestamp},{},{},{},{},{},{}",
        csv_quote(&active),
        csv_quote(&stack_json),
        csv_value(io["read_bytes"]),
        csv_value(io["write_bytes"]),
        csv_value(io["rchar"]),
        csv_value(io["wchar"]),
    )?;
    memory.flush()?;
    io_file.flush()?;
    Ok(())
}

pub struct SamplerGuard {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for SamplerGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if audit_enabled() {
            observe_temp_storage();
        }
    }
}

pub fn start_sampler(sample_ms: u64) -> Option<SamplerGuard> {
    if !enabled() {
        return None;
    }
    let memory_path = path_from_env("THINWALLET_MEMORY_CSV_PATH")?;
    let io_path = path_from_env("THINWALLET_IO_CSV_PATH")?;
    if let Some(parent) = memory_path.parent() {
        fs::create_dir_all(parent).ok()?;
    }
    let mut memory = File::create(memory_path).ok()?;
    let mut io_file = File::create(io_path).ok()?;
    writeln!(
        memory,
        "timestamp_monotonic_ns,active_phase,phase_stack,vmrss_bytes,vmhwm_bytes,vmsize_bytes,rssanon_bytes,rssfile_bytes,rssshmem_bytes,pss_bytes,pss_anon_bytes,pss_file_bytes,private_clean_bytes,private_dirty_bytes,shared_clean_bytes,shared_dirty_bytes,process_cpu_ns"
    )
    .ok()?;
    writeln!(
        io_file,
        "timestamp_monotonic_ns,active_phase,phase_stack,read_bytes,write_bytes,rchar,wchar"
    )
    .ok()?;
    sample(&mut memory, &mut io_file).ok()?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let handle = thread::spawn(move || {
        let interval = Duration::from_millis(sample_ms.max(1));
        while !thread_stop.load(Ordering::Acquire) {
            let _ = sample(&mut memory, &mut io_file);
            thread::sleep(interval);
        }
        let _ = sample(&mut memory, &mut io_file);
    });
    Some(SamplerGuard {
        stop,
        handle: Some(handle),
    })
}

// Privacy-frontier trace schema. This records identifiers and provenance only;
// no witness value, scalar, or point is written to the trace.
static TRACE_SEQ: AtomicU64 = AtomicU64::new(0);

fn trace_path() -> Option<PathBuf> {
    path_from_env("THINWALLET_TRACE_SCHEMA_PATH")
}

fn next_trace_seq() -> u64 {
    TRACE_SEQ.fetch_add(1, Ordering::Relaxed)
}

pub fn record_trace_root(id: &str) {
    let Some(path) = trace_path() else {
        return;
    };
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "root",
            "seq": next_trace_seq(),
            "id": id,
        }),
    );
}

pub fn record_trace_seed(id: &str, sec: &str) {
    debug_assert!(sec == "pub" || sec == "priv", "bad seed secrecy label");
    let Some(path) = trace_path() else {
        return;
    };
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "seed",
            "seq": next_trace_seq(),
            "id": id,
            "sec": sec,
        }),
    );
}

pub fn record_trace_event(
    id: &str,
    ins: &[&str],
    outs: &[&str],
    draws: Option<&str>,
    release: &[&str],
    public_coin: bool,
) {
    let Some(path) = trace_path() else {
        return;
    };
    increment_counter("trace_schema_events", 1);
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "event",
            "seq": next_trace_seq(),
            "timestamp_monotonic_ns": monotonic_ns(),
            "id": id,
            "in": ins,
            "out": outs,
            "draws": draws,
            "release": release,
            "public_coin": public_coin,
            "mode": std::env::var("THINWALLET_EXPERIMENT_MODE").ok(),
            "workload": std::env::var("THINWALLET_CREDENTIAL_WORKLOAD").ok(),
        }),
    );
}

pub fn record_trace_unit(name: &str, events: &[&str], rule: &str, scheme: &str) {
    let Some(path) = trace_path() else {
        return;
    };
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "unit",
            "seq": next_trace_seq(),
            "name": name,
            "events": events,
            "rule": rule,
            "scheme": scheme,
        }),
    );
}

pub fn record_trace_seal(root: &str) {
    let Some(path) = trace_path() else {
        return;
    };
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "seal",
            "seq": next_trace_seq(),
            "root": root,
        }),
    );
}

pub fn record_trace_certificate(object: &str, rule: &str, reference: &str) {
    let Some(path) = trace_path() else {
        return;
    };
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "certificate",
            "seq": next_trace_seq(),
            "object": object,
            "rule": rule,
            "ref": reference,
        }),
    );
}

pub fn record_trace_preamble_spartan(roots: &[&str]) {
    if trace_path().is_none() {
        return;
    }
    for root in roots {
        record_trace_root(root);
    }
    for (id, sec) in [
        ("pp", "pub"),
        ("circ", "pub"),
        ("x", "pub"),
        ("G", "pub"),
        ("H", "pub"),
        ("pubmeta", "pub"),
        ("w", "priv"),
    ] {
        record_trace_seed(id, sec);
    }
    for (object, rule, reference) in [
        ("comm_vars", "Hide", "Hyrax hiding row commitments"),
        ("sc_proof_phase1", "ProofProj", "app:sat-frontier-zk"),
        ("comm_claims1", "Hide", "Pedersen claim commitments"),
        ("sc_proof_phase2", "ProofProj", "app:sat-frontier-zk"),
        ("proof_eval_vars_at_ry", "ProofProj", "app:sat-frontier-zk"),
        ("pi_sat", "ProofProj", "app:sat-frontier-zk"),
        ("d_pub", "PubFun", "public eval claims and replay state"),
        (
            "comm_derefs",
            "ProofProj",
            "public sparse-matrix commitments",
        ),
        ("proof_prod_layer", "ProofProj", "app:sat-frontier-zk"),
        ("proof_hash_layer", "ProofProj", "app:sat-frontier-zk"),
        ("pi_eval", "ProofProj", "app:sat-frontier-zk"),
        ("Pi", "ProofProj", "native Spartan zero knowledge"),
    ] {
        record_trace_certificate(object, rule, reference);
    }
}
