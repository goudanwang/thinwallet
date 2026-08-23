#!/usr/bin/env python3
"""Run the reproducible Phase V4C desktop evaluation under WSL."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "libspartan"
RUNNER = ROOT / "scripts" / "run_v4c_once.sh"
RESULTS = Path(__file__).resolve().parent / "results" / "v4c"

PROFILE_S = {"S-W1": 13, "S-W2": 13, "S-W3": 14, "S-W4": 14}
PROFILE_M = {"W1": 14, "W2": 14, "W3": 14, "W4": 14}
SCALING = {
    "S-WK-1-8": 14,
    "S-WK-4-12": 15,
    "S-WK-10-16": 16,
    "S-WK-25-24": 17,
    "S-WK-52-32": 18,
}


def call(command: list[str], *, trace: bool = False) -> None:
    env = os.environ.copy()
    env["RAYON_NUM_THREADS"] = "1"
    env["V4B_TRACE_TRANSCRIPT"] = "1" if trace else "0"
    print("RUN", " ".join(command), "trace=" + str(trace), flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def run(workload: str, experiment: str, log: int, cap: str, repetition: int, *, trace: bool = False) -> None:
    call([str(RUNNER), workload, experiment, str(log), cap, str(repetition)], trace=trace)


def main() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    call(["cargo", "build", "--release", "--bin", "phase_v2_pbmo", "--bin", "phase_v4c_profile_s"])
    call([str(ROOT / "target/release/phase_v4c_profile_s"), str(RESULTS / "profile_s_audit.json")])
    security = subprocess.run(
        [str(ROOT / "target/release/phase_v2_pbmo"), "run-security-tests"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    (RESULTS / "pbmo_security_smoke.json").write_text(security.stdout.strip() + "\n")

    # Transcript evidence is retained for the four named Profile-S fixtures.
    for workload, log in PROFILE_S.items():
        for experiment in ("E0", "E3", "E4"):
            run(workload, experiment, log, "uncapped", 901, trace=True)

    # Cross-boundary evaluation uses proof-byte equality without costly JSONL traces.
    for workload, log in SCALING.items():
        for experiment in ("E0", "E3", "E4"):
            run(workload, experiment, log, "uncapped", 902)

    # Headline malicious FS6 measurements: identical warm-up, one worker, local transport.
    for workload, log in {**PROFILE_M, **PROFILE_S}.items():
        run(workload, "E4", log, "uncapped", 0)
        for repetition in range(1, 6):
            run(workload, "E4", log, "uncapped", repetition)

    # Re-run both W4 semi-honest and malicious paths five times to classify the V4B anomaly.
    for workload, log in (("W4", 14), ("S-W4", 14)):
        run(workload, "E3", log, "uncapped", 0)
        for repetition in range(1, 6):
            run(workload, "E3", log, "uncapped", repetition)

    # Controlled cap matrix. Planner rejection is recorded by the runner, not treated as a script error.
    for workload in ("W4", "S-W4"):
        for cap in (128, 192, 224, 256):
            run(workload, "E4", 14, str(cap), 801)

    (RESULTS / "evaluation_run_complete.json").write_text(
        json.dumps(
            {
                "completed": True,
                "worker_count": 1,
                "warm_up_repetitions": 1,
                "measured_repetitions": 5,
                "network_profile": "local in-process PBMO transport; no emulated network delay",
                "profile_s": PROFILE_S,
                "profile_m": PROFILE_M,
                "cross_padding": SCALING,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
