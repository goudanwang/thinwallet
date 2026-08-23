#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CREDENTIAL_KEY_BINDING_ROOT="$ROOT"

cd "$ROOT"
mkdir -p results

python3 - <<'PY'
import datetime as _datetime
import json
import os
import re
import shutil
import subprocess
import tempfile
import time


ROOT = os.environ["CREDENTIAL_KEY_BINDING_ROOT"]
BUILD = os.path.join(ROOT, "build", "credential_key_binding")
RESULTS = os.path.join(ROOT, "results")
SNARKJS = os.path.join(ROOT, "node_modules", ".bin", "snarkjs")
RUNS = 5

R1CS = os.path.join(BUILD, "credential_key_binding_main.r1cs")
WASM = os.path.join(BUILD, "credential_key_binding_main_js", "credential_key_binding_main.wasm")
WITNESS_JS = os.path.join(BUILD, "credential_key_binding_main_js", "generate_witness.js")
ZKEY = os.path.join(BUILD, "credential_key_binding_final.zkey")
VKEY = os.path.join(BUILD, "verification_key.json")
VALID_INPUT = os.path.join(ROOT, "inputs", "credential_key_binding_valid.json")
VALID_WITNESS = os.path.join(BUILD, "valid.wtns")
BENCH_WITNESS = os.path.join(BUILD, "valid_benchmark.wtns")
BENCH_PROOF = os.path.join(BUILD, "valid_benchmark_proof.json")
BENCH_PUBLIC = os.path.join(BUILD, "valid_benchmark_public.json")
EXTERNAL_VERIFY = os.path.join(BUILD, "external_signature_verify.js")


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


def time_bin():
    found = shutil.which("time")
    if found and os.path.exists(found):
        return found
    if os.path.exists("/usr/bin/time"):
        return "/usr/bin/time"
    return None


TIME_BIN = time_bin()


def parse_time_v(path):
    data = {"raw": None, "peak_rss_mb": None}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return data

    data["raw"] = raw
    match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", raw)
    if match:
        data["peak_rss_mb"] = round(int(match.group(1)) / 1024, 3)
    return data


def run_command(command):
    time_file = None
    wrapped = command
    if TIME_BIN:
        fd, time_file = tempfile.mkstemp(prefix="credential-key-binding-time-v-", text=True)
        os.close(fd)
        wrapped = [TIME_BIN, "-v", "-o", time_file] + command

    start = time.perf_counter()
    completed = subprocess.run(
        wrapped,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wall_ms = int(round((time.perf_counter() - start) * 1000))

    time_data = {"raw": None, "peak_rss_mb": None}
    if time_file:
        time_data = parse_time_v(time_file)
        try:
            os.unlink(time_file)
        except FileNotFoundError:
            pass

    return {
        "command": command,
        "command_display": " ".join(rel(part) if part.startswith(ROOT) else part for part in command),
        "wall_clock_ms": wall_ms,
        "peak_rss_mb": time_data["peak_rss_mb"],
        "time_v_output": time_data["raw"],
        "exit_status": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


required = [R1CS, WASM, WITNESS_JS, ZKEY, VKEY, VALID_WITNESS, EXTERNAL_VERIFY]
missing = [rel(path) for path in required if not os.path.exists(path)]
if missing:
    raise SystemExit("Missing build artifacts. Run scripts/build_credential_key_binding.sh first: " + ", ".join(missing))

stages = {
    "witness_generation": [
        "node",
        WITNESS_JS,
        WASM,
        VALID_INPUT,
        BENCH_WITNESS,
    ],
    "prove": [
        SNARKJS,
        "groth16",
        "prove",
        ZKEY,
        VALID_WITNESS,
        BENCH_PROOF,
        BENCH_PUBLIC,
    ],
    "verify": [
        SNARKJS,
        "groth16",
        "verify",
        VKEY,
        BENCH_PUBLIC if os.path.exists(BENCH_PUBLIC) else os.path.join(BUILD, "valid_public.json"),
        BENCH_PROOF if os.path.exists(BENCH_PROOF) else os.path.join(BUILD, "valid_proof.json"),
    ],
    "external_signature_verification": [
        "node",
        EXTERNAL_VERIFY,
    ],
}

raw = {
    "experiment": "credential_key_binding",
    "generated_at": _datetime.datetime.now(_datetime.timezone.utc).isoformat(),
    "runs_per_stage": RUNS,
    "root": ROOT,
    "peak_rss_method": "/usr/bin/time -v" if TIME_BIN else None,
    "tool_versions": {
        "circom": version(["circom", "--version"]),
        "node": version(["node", "--version"]),
        "npm": version(["npm", "--version"]),
        "python3": version(["python3", "--version"]),
        "snarkjs": version([SNARKJS, "--version"]) if os.path.exists(SNARKJS) else {"value": None, "error": "missing local snarkjs executable"},
    },
    "stages": {},
}

for stage, base_command in stages.items():
    raw["stages"][stage] = []
    print(f"Benchmarking {stage} ({RUNS} runs)...", flush=True)
    for iteration in range(1, RUNS + 1):
        command = base_command
        if stage == "verify":
            command = [
                SNARKJS,
                "groth16",
                "verify",
                VKEY,
                BENCH_PUBLIC if os.path.exists(BENCH_PUBLIC) else os.path.join(BUILD, "valid_public.json"),
                BENCH_PROOF if os.path.exists(BENCH_PROOF) else os.path.join(BUILD, "valid_proof.json"),
            ]
        result = run_command(command)
        result["iteration"] = iteration
        raw["stages"][stage].append(result)
        print(
            f"  run {iteration}: exit={result['exit_status']} "
            f"wall_ms={result['wall_clock_ms']} peak_rss_mb={result['peak_rss_mb']}",
            flush=True,
        )

raw_path = os.path.join(RESULTS, "credential_key_binding_raw.json")
with open(raw_path, "w", encoding="utf-8") as handle:
    json.dump(raw, handle, indent=2)
    handle.write("\n")

print(f"Wrote {rel(raw_path)}")
PY
