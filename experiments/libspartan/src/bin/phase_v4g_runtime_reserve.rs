use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use merlin::Transcript;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs, hint::black_box, thread};

#[derive(Clone, Serialize)]
struct MemorySnapshot {
    stage: &'static str,
    rss_bytes: Option<u64>,
    vm_hwm_bytes: Option<u64>,
    anonymous_rss_bytes: Option<u64>,
    file_rss_bytes: Option<u64>,
    pss_bytes: Option<u64>,
    threads: Option<u64>,
}

fn status_value(name: &str) -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let value = status
        .lines()
        .find(|line| line.starts_with(name))?
        .split_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()?;
    Some(if name == "Threads:" {
        value
    } else {
        value * 1024
    })
}

fn pss_bytes() -> Option<u64> {
    let rollup = fs::read_to_string("/proc/self/smaps_rollup").ok()?;
    let value = rollup
        .lines()
        .find(|line| line.starts_with("Pss:"))?
        .split_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()?;
    Some(value * 1024)
}

fn snapshot(stage: &'static str) -> MemorySnapshot {
    MemorySnapshot {
        stage,
        rss_bytes: status_value("VmRSS:"),
        vm_hwm_bytes: status_value("VmHWM:"),
        anonymous_rss_bytes: status_value("RssAnon:"),
        file_rss_bytes: status_value("RssFile:"),
        pss_bytes: pss_bytes(),
        threads: status_value("Threads:"),
    }
}

#[cfg(target_os = "linux")]
fn malloc_trim() {
    unsafe extern "C" {
        fn malloc_trim(pad: usize) -> i32;
    }
    unsafe {
        malloc_trim(0);
    }
}

#[cfg(not(target_os = "linux"))]
fn malloc_trim() {}

fn main() {
    let mut snapshots = vec![snapshot("process_startup")];

    let scalar = Scalar::from(0x5634_4701u64);
    let point = scalar * RISTRETTO_BASEPOINT_POINT;
    let mut transcript = Transcript::new(b"thinwallet/v4g/runtime-reserve");
    transcript.append_message(b"point", point.compress().as_bytes());
    let mut challenge = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut challenge);
    black_box(challenge);
    snapshots.push(snapshot("after_dependency_initialization"));

    let worker = thread::Builder::new()
        .name("thinwallet-v4g-worker".into())
        .stack_size(2 * 1024 * 1024)
        .spawn(|| {
            let mut state = vec![0u8; 256 * 1024];
            state[0] = 1;
            black_box(state);
        })
        .expect("worker initialization");
    worker.join().expect("worker join");
    snapshots.push(snapshot("after_worker_initialization"));
    snapshots.push(snapshot("before_workload"));

    let mut warmup = vec![0u8; 4 * 1024 * 1024];
    for (index, byte) in warmup.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let digest = Sha256::digest(&warmup);
    black_box(digest);
    drop(warmup);
    snapshots.push(snapshot("after_warmup"));

    malloc_trim();
    snapshots.push(snapshot("after_allocator_trim"));

    let after_dependency = &snapshots[1];
    let after_worker = &snapshots[2];
    let after_warmup = &snapshots[4];
    let after_trim = &snapshots[5];
    let subtract = |left: Option<u64>, right: Option<u64>| {
        left.zip(right)
            .map(|(left, right)| left.saturating_sub(right))
    };
    let result = serde_json::json!({
        "classification": "FINAL_RUNTIME_RESERVE_RECALIBRATED",
        "compiler_profile": "release",
        "worker_configuration": "one explicitly initialized 2 MiB worker stack; benchmark RAYON_NUM_THREADS=1",
        "snapshots": snapshots,
        "irreducible_fixed_reserve_bytes": after_trim.rss_bytes,
        "thread_stack_reserve_bytes": subtract(after_worker.vm_hwm_bytes, after_dependency.vm_hwm_bytes),
        "allocator_retained_reserve_bytes": subtract(after_warmup.rss_bytes, after_trim.rss_bytes),
        "workload_dependent_reserve_bytes": null,
        "notes": [
            "VmHWM is monotone and is not used as the post-trim current reserve.",
            "Workload-dependent reserve is calibrated separately from this workload-free executable."
        ]
    });
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}
