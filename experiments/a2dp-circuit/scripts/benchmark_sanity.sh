#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SANITY_ROOT="$ROOT"

cd "$ROOT"
mkdir -p results

python3 - <<'PY'
import datetime as _datetime
import json
import os
import shutil
import subprocess
import tempfile
import time


ROOT = os.environ["SANITY_ROOT"]
BUILD = os.path.join(ROOT, "build")
RESULTS = os.path.join(ROOT, "results")
SNARKJS = os.path.join(ROOT, "node_modules", ".bin", "snarkjs")
RUNS = 5


def rel(path):
    return os.path.relpath(path, ROOT)


def version(command):
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
    except Exception as exc:
        return {"value": None, "error": str(exc)}

    output = (completed.stdout or completed.stderr).strip().splitlines()
    return {
        "value": output[0] if output else None,
        "exit_status": completed.returncode,
    }


def has_gnu_time():
    time_bin = shutil.which("time")
    if not time_bin:
        return None
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name
    try:
        probe = subprocess.run(
            [time_bin, "-f", "%e %M", "-o", tmp_path, "true"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if probe.returncode != 0:
            return None
        with open(tmp_path, "r", encoding="utf-8", errors="replace") as handle:
            fields = handle.read().strip().split()
        if len(fields) >= 2:
            return time_bin
    finally:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
    return None


TIME_BIN = has_gnu_time()


def run_command(command):
    time_file = None
    wrapped = command
    if TIME_BIN:
        fd, time_file = tempfile.mkstemp(prefix="sanity-time-", text=True)
        os.close(fd)
        wrapped = [TIME_BIN, "-f", "%e %M", "-o", time_file] + command

    start = time.perf_counter()
    completed = subprocess.run(
        wrapped,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    elapsed_ms = int(round((time.perf_counter() - start) * 1000))

    peak_rss_mb = None
    if time_file:
        try:
            with open(time_file, "r", encoding="utf-8", errors="replace") as handle:
                fields = handle.read().strip().split()
            if len(fields) >= 2:
                peak_rss_mb = round(int(fields[1]) / 1024, 3)
        except Exception:
            peak_rss_mb = None
        finally:
            try:
                os.unlink(time_file)
            except FileNotFoundError:
                pass

    return {
        "command": command,
        "wall_clock_ms": elapsed_ms,
        "peak_rss_mb": peak_rss_mb,
        "exit_status": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


stages = {
    "witness_generation": [
        "node",
        os.path.join(BUILD, "sanity_multiplier_js", "generate_witness.js"),
        os.path.join(BUILD, "sanity_multiplier_js", "sanity_multiplier.wasm"),
        os.path.join(ROOT, "inputs", "sanity_multiplier.json"),
        os.path.join(BUILD, "sanity_multiplier.wtns"),
    ],
    "prove": [
        SNARKJS,
        "groth16",
        "prove",
        os.path.join(BUILD, "sanity_multiplier_final.zkey"),
        os.path.join(BUILD, "sanity_multiplier.wtns"),
        os.path.join(BUILD, "proof.json"),
        os.path.join(BUILD, "public.json"),
    ],
    "verify": [
        SNARKJS,
        "groth16",
        "verify",
        os.path.join(BUILD, "verification_key.json"),
        os.path.join(BUILD, "public.json"),
        os.path.join(BUILD, "proof.json"),
    ],
}

raw = {
    "experiment": "sanity_multiplier",
    "generated_at": _datetime.datetime.now(_datetime.timezone.utc).isoformat(),
    "runs_per_stage": RUNS,
    "root": ROOT,
    "peak_rss_method": "/usr/bin/time -f %M" if TIME_BIN else None,
    "tool_versions": {
        "circom": version(["circom", "--version"]),
        "node": version(["node", "--version"]),
        "npm": version(["npm", "--version"]),
        "python3": version(["python3", "--version"]),
        "snarkjs": version([SNARKJS, "--version"]) if os.path.exists(SNARKJS) else {"value": None, "error": "missing local snarkjs executable"},
    },
    "stages": {},
}

for stage, command in stages.items():
    raw["stages"][stage] = []
    print(f"Benchmarking {stage} ({RUNS} runs)...", flush=True)
    for iteration in range(1, RUNS + 1):
        result = run_command(command)
        result["iteration"] = iteration
        result["command_display"] = " ".join(rel(part) if part.startswith(ROOT) else part for part in command)
        raw["stages"][stage].append(result)
        print(
            f"  run {iteration}: exit={result['exit_status']} "
            f"wall_ms={result['wall_clock_ms']} peak_rss_mb={result['peak_rss_mb']}",
            flush=True,
        )

raw_path = os.path.join(RESULTS, "sanity_raw.json")
with open(raw_path, "w", encoding="utf-8") as handle:
    json.dump(raw, handle, indent=2)
    handle.write("\n")

print(f"Wrote {rel(raw_path)}")
PY
