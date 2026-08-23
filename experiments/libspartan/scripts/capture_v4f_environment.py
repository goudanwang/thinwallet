#!/usr/bin/env python3
import json
import os
import platform
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def command(*args):
    try:
        return subprocess.run(args, check=False, text=True, capture_output=True).stdout.strip() or None
    except OSError:
        return None


def files(pattern):
    values = {}
    for path in sorted(Path("/sys").glob(pattern)):
        try: values[str(path)] = path.read_text().strip()
        except OSError: values[str(path)] = None
    return values


payload = {
    "platform": platform.platform(),
    "uname": command("uname", "-a"),
    "os_release": Path("/etc/os-release").read_text() if Path("/etc/os-release").exists() else None,
    "cpu": command("lscpu", "-J"),
    "memory": command("free", "-b"),
    "filesystem": command("findmnt", "-T", str(ROOT), "-J"),
    "cpu_affinity_policy": "scheduler default; no taskset restriction; identical for all runs",
    "worker_count": 1,
    "warmup_policy": "no discarded prover warm-up; repeated cells run serially in fixed order",
    "filesystem_cache_policy": "OS cache retained; no drop_caches between repetitions",
    "competing_process_policy": "one ThinWallet prover at a time; host-side activity is not controllable from WSL",
    "network_profile": "local in-process PBMO for prover measurements",
    "logging_policy": "no transcript tracing in performance repetitions",
    "cpu_frequency_khz": files("devices/system/cpu/cpu*/cpufreq/scaling_cur_freq"),
    "thermal_state": files("class/thermal/thermal_zone*/temp"),
    "thermal_state_note": "null/empty when WSL does not expose physical sensors",
    "android_execution": "NOT_PERFORMED",
}
output = ROOT / "results/v4f/environment.json"
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(payload, indent=2) + "\n")
print(output)
