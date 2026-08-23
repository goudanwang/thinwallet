use anyhow::{anyhow, Context, Result};
use libspartan_patched::remote_eval::{
    configure_benchmark_threads, run_eval_benchmark, EvalBenchmarkConfig,
};
use std::env;
use std::fs;
use std::path::PathBuf;

fn value(args: &[String], name: &str) -> Result<String> {
    let index = args
        .iter()
        .position(|arg| arg == name)
        .ok_or_else(|| anyhow!("missing {name}"))?;
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| anyhow!("missing value for {name}"))
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn decode_hex_32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(anyhow!("deterministic seed must contain 64 hex characters"));
    }
    let mut output = [0u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .context("invalid deterministic seed hex")?;
    }
    Ok(output)
}

#[cfg(target_os = "linux")]
fn pin_cpus(specification: &str) -> Result<()> {
    let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    unsafe { libc::CPU_ZERO(&mut set) };
    for part in specification.split(',') {
        let (start, end) = part.split_once('-').unwrap_or((part, part));
        let start = start.parse::<usize>()?;
        let end = end.parse::<usize>()?;
        for cpu in start..=end {
            unsafe { libc::CPU_SET(cpu, &mut set) };
        }
    }
    let status =
        unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) };
    if status != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn pin_cpus(_specification: &str) -> Result<()> {
    Err(anyhow!("CPU pinning is only supported on Linux"))
}

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let fixture = PathBuf::from(value(&args, "--fixture")?);
    let threads = value(&args, "--threads")?.parse::<usize>()?;
    let warmup = value(&args, "--warmup")?.parse::<usize>()?;
    let runs = value(&args, "--runs")?.parse::<usize>()?;
    let cache_mode = value(&args, "--cache-mode")?;
    if cache_mode != "warm" {
        return Err(anyhow!("only --cache-mode warm is supported"));
    }
    let output = PathBuf::from(value(&args, "--output")?);
    let deterministic_eval_root = decode_hex_32(&value(&args, "--deterministic-eval-seed")?)?;
    let eval_store = value(&args, "--eval-store").unwrap_or_else(|_| "current".to_owned());
    if !matches!(
        eval_store.as_str(),
        "current" | "ext4" | "tmpfs" | "memory" | "batched-file"
    ) {
        return Err(anyhow!("unsupported --eval-store {eval_store}"));
    }
    let state_root = value(&args, "--state-root").ok().map(PathBuf::from);
    if let Ok(cpus) = value(&args, "--pin-cpus") {
        pin_cpus(&cpus)?;
    }
    configure_benchmark_threads(threads)
        .map_err(|error| anyhow!("configure persistent Rayon pool: {error}"))?;
    let work_dir = output
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(format!("work-t{threads}"));
    if work_dir.exists() {
        fs::remove_dir_all(&work_dir)?;
    }
    run_eval_benchmark(EvalBenchmarkConfig {
        fixture,
        threads,
        warmup,
        runs,
        output,
        work_dir,
        deterministic_eval_root,
        eval_store,
        state_root,
        report_stage_timings: flag(&args, "--report-stage-timings"),
        report_worker_utilization: flag(&args, "--report-worker-utilization"),
    })
    .map_err(|error| anyhow!(error))
}
