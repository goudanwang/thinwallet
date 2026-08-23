#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

mode="${1:?expected FS3 or FS4}"
log_size="${2:?expected log size}"
cap_mib="${3:?expected cap MiB or uncapped}"
repetition="${4:-1}"

case "$mode" in
  FS3) active_streaming=0 ;;
  FS4) active_streaming=1 ;;
  *) echo "invalid mode: $mode" >&2; exit 2 ;;
esac

runner="$PWD/target/release/phase_v2_pbmo"
out_dir="$PWD/results/v3c_boundary"
session="${mode}-${log_size}-${cap_mib}-${repetition}-$$"
state_root="/tmp/thinwallet-v3c-$session"
prefix="$out_dir/${mode}_${log_size}_${cap_mib}_r${repetition}"
mkdir -p "$out_dir" "$state_root/v3a" "$state_root/v3b"
rm -f "${prefix}.stdout" "${prefix}.stderr" "${prefix}.v3a-store.jsonl" \
  "${prefix}.v3b-store.json" "${prefix}.plan.json" "${prefix}.json" \
  "${prefix}.proof.json" "${prefix}.proof.bin" "${prefix}.verify.json" \
  "${prefix}.verify.stderr"

cleanup() {
  case "$state_root" in
    /tmp/thinwallet-v3c-*) find "$state_root" -type f -delete 2>/dev/null || true
      find "$state_root" -depth -type d -empty -delete 2>/dev/null || true ;;
  esac
}
trap cleanup EXIT INT TERM

run_backend() {
  env \
    LIBSPARTAN_FIXED_STREAMING=1 \
    LIBSPARTAN_MULTI_TARGET_STREAMING=1 \
    LIBSPARTAN_ACTIVE_STATE_STREAMING="$active_streaming" \
    V3A_STATE_DIR="$state_root/v3a" \
    V3A_STATE_SESSION="$session" \
    V3A_STATE_REPORT_PATH="${prefix}.v3a-store.jsonl" \
    V3B_STATE_DIR="$state_root/v3b" \
    V3B_STATE_SESSION="$session" \
    V3B_STATE_REPORT_PATH="${prefix}.v3b-store.json" \
    V3B_PLAN_REPORT_PATH="${prefix}.plan.json" \
    V3B_HARD_LIMIT_BYTES="$hard_limit_bytes" \
    V3B_RESERVED_RUNTIME_BYTES="$((111 * 1024 * 1024))" \
    THINWALLET_DEFER_UPSTREAM_VERIFY="$active_streaming" \
    THINWALLET_PROOF_OUT="${prefix}.proof.bin" \
    THINWALLET_RESULT_OUT="${prefix}.proof.json" \
    /usr/bin/time -v "$runner" malicious "$log_size"
}

if [[ "$cap_mib" == uncapped ]]; then
  hard_limit_bytes="$((8 * 1024 * 1024 * 1024))"
else
  hard_limit_bytes="$((cap_mib * 1024 * 1024))"
fi

start_ns=$(date +%s%N)
set +e
if [[ "$cap_mib" == uncapped ]]; then
  run_backend >"${prefix}.stdout" 2>"${prefix}.stderr"
else
  (ulimit -v "$((cap_mib * 1024))"; run_backend) \
    >"${prefix}.stdout" 2>"${prefix}.stderr"
fi
status=$?
set -e
end_ns=$(date +%s%N)

verify_status=null
if [[ $status -eq 0 && "$active_streaming" == 1 ]]; then
  set +e
  "$runner" verify-proof "${prefix}.proof.bin" "$log_size" \
    >"${prefix}.verify.json" 2>"${prefix}.verify.stderr"
  verify_status=$?
  set -e
fi

python3 - "$prefix" "$mode" "$log_size" "$cap_mib" "$repetition" \
  "$status" "$start_ns" "$end_ns" "$verify_status" <<'PY'
import json
import re
import sys
from pathlib import Path

prefix, mode, logn, cap, rep, status, start, end, verify_status = sys.argv[1:]
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

store = load_json(".v3b-store.json")
proof = load_json(".proof.json")
verify_path = Path(prefix + ".verify.json")
external_verify = None
if verify_path.exists():
    lines = [line for line in verify_path.read_text().splitlines() if line]
    external_verify = json.loads(lines[-1]) if lines else None
data = {
    "fs_mode": mode,
    "log_size": int(logn),
    "relation_size": 1 << int(logn),
    "cap_mib": None if cap == "uncapped" else int(cap),
    "repetition": int(rep),
    "exit_status": int(status),
    "completed": int(status) == 0,
    "failure_kind": failure,
    "wall_clock_ms": (int(end) - int(start)) / 1e6,
    "peak_rss_kib": timed("Maximum resident set size (kbytes)"),
    "major_page_faults": timed("Major (requiring I/O) page faults"),
    "minor_page_faults": timed("Minor (reclaiming a frame) page faults"),
    "filesystem_inputs": timed("File system inputs"),
    "filesystem_outputs": timed("File system outputs"),
    "swaps": timed("Swaps"),
    "proof": proof,
    "external_upstream_verifier": external_verify,
    "external_upstream_verifier_exit_status": (
        None if verify_status == "null" else int(verify_status)
    ),
    "state_store": store,
    "memory_plan": load_json(".plan.json"),
}
Path(prefix + ".json").write_text(json.dumps(data, indent=2) + "\n")
print(json.dumps({key: data[key] for key in (
    "fs_mode", "log_size", "cap_mib", "repetition", "exit_status",
    "completed", "failure_kind", "wall_clock_ms", "peak_rss_kib"
)}, separators=(",", ":")))
PY

exit 0
