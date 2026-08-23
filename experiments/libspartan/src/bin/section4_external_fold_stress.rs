use anyhow::{Context, Result};
use libspartan_patched::multi_state_store::{
    MultiObjectFileBackedStateStore, MultiObjectStoreConfig, ProverStateStore, StateDurability,
};
use libspartan_patched::streaming_sumcheck_fold::{StreamingPolynomial, StreamingScalar as Scalar};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const SCALAR_WIDTH_BYTES: usize = 32;

#[derive(Serialize)]
struct RoundResult {
    round: usize,
    b: usize,
    scalar_width_bytes: usize,
    input_elements: usize,
    output_elements: usize,
    input_resident_elements: usize,
    output_resident_elements: usize,
    predicted_working_set_bound_bytes: usize,
    measured_fold_buffer_peak_bytes: usize,
    logical_read_bytes: u64,
    logical_write_bytes: u64,
    input_chunks: u64,
    output_chunks: u64,
    wall_ms: f64,
    process_cpu_ms: f64,
}

#[derive(Serialize)]
struct StressResult {
    experiment: &'static str,
    classification: &'static str,
    relation: &'static str,
    table_elements: usize,
    forced_external_fold_rounds: usize,
    scalar_width_bytes: usize,
    maximum_chunk_bytes: usize,
    chunk_elements: usize,
    resident_fold_wall_ms: f64,
    resident_fold_process_cpu_ms: f64,
    external_fold_wall_ms: f64,
    external_fold_process_cpu_ms: f64,
    measured_peak_rss_bytes: u64,
    measured_peak_pss_bytes: Option<u64>,
    logical_read_bytes_total: u64,
    logical_write_bytes_total: u64,
    temporary_storage_peak_bytes: u64,
    resident_external_outputs_equal: bool,
    rounds: Vec<RoundResult>,
}

fn process_cpu_ns() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut value) };
    if result != 0 {
        return 0;
    }
    (value.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(value.tv_nsec as u64)
}

fn proc_kib(path: &str, key: &str) -> Option<u64> {
    fs::read_to_string(path).ok()?.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?;
        rest.split_whitespace().next()?.parse::<u64>().ok()
    })
}

fn start_memory_sampler() -> (
    Arc<AtomicBool>,
    Arc<AtomicU64>,
    Arc<AtomicU64>,
    thread::JoinHandle<()>,
) {
    let running = Arc::new(AtomicBool::new(true));
    let peak_rss_kib = Arc::new(AtomicU64::new(0));
    let peak_pss_kib = Arc::new(AtomicU64::new(0));
    let thread_running = Arc::clone(&running);
    let thread_rss = Arc::clone(&peak_rss_kib);
    let thread_pss = Arc::clone(&peak_pss_kib);
    let handle = thread::spawn(move || {
        while thread_running.load(Ordering::Relaxed) {
            if let Some(value) = proc_kib("/proc/self/status", "VmRSS:") {
                thread_rss.fetch_max(value, Ordering::Relaxed);
            }
            if let Some(value) = proc_kib("/proc/self/smaps_rollup", "Pss:") {
                thread_pss.fetch_max(value, Ordering::Relaxed);
            }
            thread::sleep(Duration::from_millis(2));
        }
    });
    (running, peak_rss_kib, peak_pss_kib, handle)
}

fn dense_fold(values: &mut Vec<Scalar>, challenge: Scalar) {
    let half = values.len() / 2;
    for index in 0..half {
        values[index] = values[index] + challenge * (values[index + half] - values[index]);
    }
    values.truncate(half);
}

fn main() -> Result<()> {
    let output = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("results/section4_external_fold_stress.json"));
    let table_elements = 1usize << 18;
    let fold_rounds = 4usize;
    let maximum_chunk_bytes = 1024 * 1024;
    let chunk_elements = maximum_chunk_bytes / SCALAR_WIDTH_BYTES;
    let values = (0..table_elements)
        .map(|index| Scalar::from((index as u64).wrapping_mul(17).wrapping_add(3)))
        .collect::<Vec<_>>();
    let challenges = (0..fold_rounds)
        .map(|round| Scalar::from((round as u64 + 1) * 29))
        .collect::<Vec<_>>();

    let mut resident = values.clone();
    let resident_wall = Instant::now();
    let resident_cpu = process_cpu_ns();
    for challenge in &challenges {
        dense_fold(&mut resident, *challenge);
    }
    let resident_cpu_ms = process_cpu_ns().saturating_sub(resident_cpu) as f64 / 1_000_000.0;
    let resident_wall_ms = resident_wall.elapsed().as_secs_f64() * 1000.0;

    let root = std::env::temp_dir().join(format!(
        "thinwallet-section4-fold-stress-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    let mut store = MultiObjectFileBackedStateStore::create(MultiObjectStoreConfig {
        root: root.clone(),
        proof_session: "external-fold-stress".to_owned(),
        backend_revision: "libspartan-0.9.0-section4".to_owned(),
        metadata_key: [0x71; 32],
        maximum_chunk_bytes,
        maximum_temporary_storage_bytes: 64 * 1024 * 1024,
        durability: StateDurability::SecurityCriticalDurable,
    })?;
    let mut external =
        StreamingPolynomial::write(&mut store, "round-0", "Section4ExternalFoldStress", &values)?;
    drop(values);

    let (running, peak_rss_kib, peak_pss_kib, sampler) = start_memory_sampler();
    let external_wall = Instant::now();
    let external_cpu = process_cpu_ns();
    let mut rounds = Vec::new();
    for (round, challenge) in challenges.iter().enumerate() {
        let input_elements = external.scalar_count;
        let output_elements = input_elements / 2;
        let b = output_elements;
        let active_chunk_elements = chunk_elements.min(output_elements);
        let wall = Instant::now();
        let cpu = process_cpu_ns();
        let stats =
            external.fold_top(&mut store, format!("round-{}", round + 1), challenge, round)?;
        rounds.push(RoundResult {
            round,
            b,
            scalar_width_bytes: SCALAR_WIDTH_BYTES,
            input_elements,
            output_elements,
            input_resident_elements: active_chunk_elements * 2,
            output_resident_elements: active_chunk_elements,
            predicted_working_set_bound_bytes: active_chunk_elements * SCALAR_WIDTH_BYTES * 4,
            measured_fold_buffer_peak_bytes: stats.peak_buffer_bytes,
            logical_read_bytes: stats.read_bytes,
            logical_write_bytes: stats.write_bytes,
            input_chunks: stats.input_chunks,
            output_chunks: stats.output_chunks,
            wall_ms: wall.elapsed().as_secs_f64() * 1000.0,
            process_cpu_ms: process_cpu_ns().saturating_sub(cpu) as f64 / 1_000_000.0,
        });
    }
    let external_cpu_ms = process_cpu_ns().saturating_sub(external_cpu) as f64 / 1_000_000.0;
    let external_wall_ms = external_wall.elapsed().as_secs_f64() * 1000.0;
    running.store(false, Ordering::Relaxed);
    sampler.join().expect("memory sampler panicked");

    let output_values = external.read_all(&mut store)?;
    let outputs_equal = output_values == resident;
    let store_stats = store.stats();
    let logical_read_bytes_total = rounds.iter().map(|round| round.logical_read_bytes).sum();
    let logical_write_bytes_total = rounds.iter().map(|round| round.logical_write_bytes).sum();
    store.abort_session_cleanup()?;
    let _ = fs::remove_dir_all(root);

    let result = StressResult {
        experiment: "section4_external_fold_stress",
        classification: "DEDICATED_MICROBENCHMARK_NOT_H1_H2",
        relation: "same multilinear table and challenges for resident and external top folds",
        table_elements,
        forced_external_fold_rounds: fold_rounds,
        scalar_width_bytes: SCALAR_WIDTH_BYTES,
        maximum_chunk_bytes,
        chunk_elements,
        resident_fold_wall_ms: resident_wall_ms,
        resident_fold_process_cpu_ms: resident_cpu_ms,
        external_fold_wall_ms: external_wall_ms,
        external_fold_process_cpu_ms: external_cpu_ms,
        measured_peak_rss_bytes: peak_rss_kib.load(Ordering::Relaxed) * 1024,
        measured_peak_pss_bytes: match peak_pss_kib.load(Ordering::Relaxed) {
            0 => None,
            value => Some(value * 1024),
        },
        logical_read_bytes_total,
        logical_write_bytes_total,
        temporary_storage_peak_bytes: store_stats.temporary_storage_peak_bytes,
        resident_external_outputs_equal: outputs_equal,
        rounds,
    };
    if !outputs_equal {
        anyhow::bail!("resident and external fold outputs differ");
    }
    if let Some(parent) = Path::new(&output).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, serde_json::to_vec_pretty(&result)?)
        .with_context(|| format!("write {}", output.display()))?;
    println!("{}", output.display());
    Ok(())
}
