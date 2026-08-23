#!/usr/bin/env python3
"""Measure unchanged upstream verifier CLI latency and RSS for V4C fixtures."""

from __future__ import annotations

import json
import math
import os
import re
import statistics
import subprocess
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent / "libspartan"
BIN = ROOT / "target/release/phase_v2_pbmo"
RUNS = HERE / "results/v4c/runs"
OUT = HERE / "results/v4c/verifier_benchmark.json"
WORKLOADS = {"W1": 14, "W2": 14, "W3": 14, "W4": 14, "S-W1": 13, "S-W2": 13, "S-W3": 14, "S-W4": 14}
T95_N5 = 2.7764451051977987


def summary(values: list[float]) -> dict:
    mean = statistics.mean(values)
    sd = statistics.stdev(values)
    margin = T95_N5 * sd / math.sqrt(len(values))
    return {
        "raw": values,
        "mean": mean,
        "median": statistics.median(values),
        "standard_deviation": sd,
        "minimum": min(values),
        "maximum": max(values),
        "confidence_interval_95": [mean - margin, mean + margin],
    }


def once(workload: str, log: int, proof: Path) -> tuple[float, float | None, int, bool]:
    env = os.environ.copy()
    env["THINWALLET_CREDENTIAL_WORKLOAD"] = workload
    start = time.perf_counter_ns()
    result = subprocess.run(
        ["/usr/bin/time", "-v", str(BIN), "verify-proof", str(proof), str(log)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )
    elapsed_ms = (time.perf_counter_ns() - start) / 1e6
    match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", result.stderr)
    rss_kib = float(match.group(1)) if match else None
    accepted = False
    if result.returncode == 0:
        try:
            accepted = bool(json.loads(result.stdout)["accepted"])
        except (json.JSONDecodeError, KeyError):
            accepted = False
    return elapsed_ms, rss_kib, result.returncode, accepted


def main() -> None:
    data = {}
    for workload, log in WORKLOADS.items():
        safe = workload.replace("-", "_")
        proof = RUNS / f"{safe}_E4_uncapped_r1.proof.bin"
        if not proof.exists():
            raise SystemExit(f"missing proof: {proof}")
        once(workload, log, proof)  # warm-up
        times, rss, statuses, accepts = [], [], [], []
        for _ in range(5):
            elapsed, peak, status, accepted = once(workload, log, proof)
            times.append(elapsed)
            if peak is not None:
                rss.append(peak)
            statuses.append(status)
            accepts.append(accepted)
        data[workload] = {
            "proof_size_bytes": proof.stat().st_size,
            "latency_ms": summary(times),
            "peak_rss_kib": summary(rss) if len(rss) == 5 else None,
            "exit_status": statuses,
            "accepted": accepts,
            "unchanged_verifier": "upstream libspartan 0.9.0",
        }
    report = {
        "measurement": "cold-process unchanged-verifier CLI latency; process launch is included",
        "warm_up_runs": 1,
        "measured_runs": 5,
        "workloads": data,
        "all_passed": all(all(item["accepted"]) and not any(item["exit_status"]) for item in data.values()),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2) + "\n")
    print(OUT)


if __name__ == "__main__":
    main()
