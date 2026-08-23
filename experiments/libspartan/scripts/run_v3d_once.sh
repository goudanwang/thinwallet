#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

fs_mode="${1:?expected FS4 or FS5}"
provider="${2:?expected semi or malicious}"
log_size="${3:?expected log size}"
cap_mib="${4:?expected cap MiB or uncapped}"
repetition="${5:-0}"

case "$fs_mode" in
  FS4) recompute=0; ephemeral=0 ;;
  FS5) recompute=1; ephemeral=1 ;;
  *) echo "invalid FS mode: $fs_mode" >&2; exit 2 ;;
esac
case "$provider" in
  semi|malicious) ;;
  *) echo "invalid PBMO provider: $provider" >&2; exit 2 ;;
esac

runner="$PWD/target/release/phase_v2_pbmo"
out_dir="$PWD/results/v3d_boundary"
session="${fs_mode}-${provider}-${log_size}-${cap_mib}-${repetition}-$$"
state_root="/tmp/thinwallet-v3d-$session"
prefix="$out_dir/${fs_mode}_${provider}_${log_size}_${cap_mib}_r${repetition}"
mkdir -p "$out_dir" "$state_root/v3a" "$state_root/v3b"
rm -f "${prefix}."{stdout,stderr,v3a-store.jsonl,v3b-store.json,plan.json,json,proof.bin,proof.json,verify.json,verify.stderr,transcript.jsonl}

cleanup() {
  case "$state_root" in
    /tmp/thinwallet-v3d-*) find "$state_root" -type f -delete 2>/dev/null || true
      find "$state_root" -depth -type d -empty -delete 2>/dev/null || true ;;
  esac
}
trap cleanup EXIT INT TERM

if [[ "$cap_mib" == uncapped ]]; then
  hard_limit_bytes="$((8 * 1024 * 1024 * 1024))"
else
  hard_limit_bytes="$((cap_mib * 1024 * 1024))"
fi

if [[ "${V3D_TRACE_TRANSCRIPT:-0}" == 1 ]]; then
  export V3A_TRANSCRIPT_TRACE_PATH="${prefix}.transcript.jsonl"
else
  unset V3A_TRANSCRIPT_TRACE_PATH
fi

run_backend() {
  env \
    LIBSPARTAN_FIXED_STREAMING=1 \
    LIBSPARTAN_MULTI_TARGET_STREAMING=1 \
    LIBSPARTAN_ACTIVE_STATE_STREAMING=1 \
    LIBSPARTAN_TRANSCRIPT_RECOMPUTE="$recompute" \
    LIBSPARTAN_EPHEMERAL_STATE="$ephemeral" \
    RAYON_NUM_THREADS=1 \
    V3A_STATE_DIR="$state_root/v3a" \
    V3A_STATE_SESSION="$session" \
    V3A_STATE_REPORT_PATH="${prefix}.v3a-store.jsonl" \
    V3B_STATE_DIR="$state_root/v3b" \
    V3B_STATE_SESSION="$session" \
    V3B_STATE_REPORT_PATH="${prefix}.v3b-store.json" \
    V3B_PLAN_REPORT_PATH="${prefix}.plan.json" \
    V3B_HARD_LIMIT_BYTES="$hard_limit_bytes" \
    V3B_RESERVED_RUNTIME_BYTES="$((111 * 1024 * 1024))" \
    THINWALLET_DEFER_UPSTREAM_VERIFY=1 \
    THINWALLET_PROOF_OUT="${prefix}.proof.bin" \
    THINWALLET_RESULT_OUT="${prefix}.proof.json" \
    /usr/bin/time -v "$runner" "$provider" "$log_size"
}

start_ns=$(date +%s%N)
set +e
if [[ "$cap_mib" == uncapped ]]; then
  run_backend >"${prefix}.stdout" 2>"${prefix}.stderr"
else
  (ulimit -v "$((cap_mib * 1024))"; run_backend) >"${prefix}.stdout" 2>"${prefix}.stderr"
fi
status=$?
set -e
end_ns=$(date +%s%N)

verify_status=null
if [[ $status -eq 0 ]]; then
  set +e
  "$runner" verify-proof "${prefix}.proof.bin" "$log_size" \
    >"${prefix}.verify.json" 2>"${prefix}.verify.stderr"
  verify_status=$?
  set -e
fi

python3 - "$prefix" "$fs_mode" "$provider" "$log_size" "$cap_mib" "$repetition" \
  "$status" "$start_ns" "$end_ns" "$verify_status" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

prefix, mode, provider, logn, cap, rep, status, start, end, verify_status = sys.argv[1:]
stderr = Path(prefix + ".stderr").read_text(errors="replace")

def timed(label):
    match = re.search(rf"^\s*{re.escape(label)}:\s*([0-9.]+)\s*$", stderr, re.M)
    return float(match.group(1)) if match else None

def load_json(suffix):
    path = Path(prefix + suffix)
    return json.loads(path.read_text()) if path.exists() else None

failure = None
if int(status):
    if "controlled plan rejection" in stderr:
        failure = "controlled_budget_rejection"
    elif "memory allocation of" in stderr:
        failure = "allocator_failure"
    elif re.search(r"\bKilled\b", stderr):
        failure = "oom_killed"
    elif "panicked at" in stderr:
        failure = "panic"
    else:
        failure = "nonzero_exit"

proof_path = Path(prefix + ".proof.bin")
transcript_path = Path(prefix + ".transcript.jsonl")
external_verify = None
verify_path = Path(prefix + ".verify.json")
if verify_path.exists():
    lines = [line for line in verify_path.read_text().splitlines() if line]
    external_verify = json.loads(lines[-1]) if lines else None

data = {
    "fs_mode": mode,
    "pbmo_mode": provider,
    "log_size": int(logn),
    "relation_size": 1 << int(logn),
    "cap_mib": None if cap == "uncapped" else int(cap),
    "repetition": int(rep),
    "exit_status": int(status),
    "completed": int(status) == 0,
    "failure_kind": failure,
    "wall_clock_ms": (int(end) - int(start)) / 1e6,
    "user_cpu_seconds": timed("User time (seconds)"),
    "system_cpu_seconds": timed("System time (seconds)"),
    "peak_rss_kib": timed("Maximum resident set size (kbytes)"),
    "swaps": timed("Swaps"),
    "filesystem_inputs": timed("File system inputs"),
    "filesystem_outputs": timed("File system outputs"),
    "proof_sha256": hashlib.sha256(proof_path.read_bytes()).hexdigest() if proof_path.exists() else None,
    "proof_size_bytes": proof_path.stat().st_size if proof_path.exists() else None,
    "transcript_sha256": hashlib.sha256(transcript_path.read_bytes()).hexdigest() if transcript_path.exists() else None,
    "transcript_events": sum(1 for _ in transcript_path.open()) if transcript_path.exists() else None,
    "patched_result": load_json(".proof.json"),
    "external_upstream_verifier": external_verify,
    "external_upstream_verifier_exit_status": None if verify_status == "null" else int(verify_status),
    "state_store": load_json(".v3b-store.json"),
    "memory_plan": load_json(".plan.json"),
}
Path(prefix + ".json").write_text(json.dumps(data, indent=2) + "\n")
print(json.dumps({key: data[key] for key in (
    "fs_mode", "pbmo_mode", "log_size", "cap_mib", "repetition", "exit_status",
    "completed", "failure_kind", "wall_clock_ms", "peak_rss_kib", "proof_sha256",
    "transcript_sha256"
)}, separators=(",", ":")))
PY

exit 0
