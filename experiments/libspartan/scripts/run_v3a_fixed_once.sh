#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

fs_mode="${1:?expected FS0, FS1, or FS2}"
log_size="${2:?expected log size}"
cap_mib="${3:?expected cap MiB or uncapped}"
repetition="${4:-1}"

case "$fs_mode" in
  FS0) backend_mode=upstream ;;
  FS1|FS2) backend_mode=semi ;;
  *) echo "invalid fixed-streaming mode: $fs_mode" >&2; exit 2 ;;
esac

runner="$PWD/target/release/phase_v2_pbmo"
out_dir="$PWD/results/v3a_boundary"
state_dir="$PWD/results/v3a_state/${fs_mode}-${log_size}-${cap_mib}-${repetition}"
prefix="$out_dir/${fs_mode}_${log_size}_${cap_mib}_r${repetition}"
mkdir -p "$out_dir" "$state_dir"
rm -f "${prefix}.stdout" "${prefix}.stderr" "${prefix}.store.jsonl" "${prefix}.json"

cleanup() {
  if [[ "$state_dir" == "$PWD/results/v3a_state/"* ]]; then
    find "$state_dir" -type f -delete 2>/dev/null || true
    rmdir "$state_dir" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

start_ns=$(date +%s%N)
set +e
if [[ "$cap_mib" == uncapped ]]; then
  if [[ "$fs_mode" == FS2 ]]; then
    LIBSPARTAN_FIXED_STREAMING=1 \
      V3A_STATE_DIR="$state_dir" \
      V3A_STATE_SESSION="${fs_mode}-${log_size}-${cap_mib}-${repetition}" \
      V3A_STATE_REPORT_PATH="${prefix}.store.jsonl" \
      /usr/bin/time -v "$runner" "$backend_mode" "$log_size" \
      >"${prefix}.stdout" 2>"${prefix}.stderr"
  else
    /usr/bin/time -v "$runner" "$backend_mode" "$log_size" \
      >"${prefix}.stdout" 2>"${prefix}.stderr"
  fi
else
  if [[ "$fs_mode" == FS2 ]]; then
    (
      ulimit -v "$((cap_mib * 1024))"
      LIBSPARTAN_FIXED_STREAMING=1 \
        V3A_STATE_DIR="$state_dir" \
        V3A_STATE_SESSION="${fs_mode}-${log_size}-${cap_mib}-${repetition}" \
        V3A_STATE_REPORT_PATH="${prefix}.store.jsonl" \
        /usr/bin/time -v "$runner" "$backend_mode" "$log_size"
    ) >"${prefix}.stdout" 2>"${prefix}.stderr"
  else
    (
      ulimit -v "$((cap_mib * 1024))"
      /usr/bin/time -v "$runner" "$backend_mode" "$log_size"
    ) >"${prefix}.stdout" 2>"${prefix}.stderr"
  fi
fi
status=$?
set -e
end_ns=$(date +%s%N)

result_path="results/v2_${log_size}_${backend_mode}.json"
if [[ $status -eq 0 && -f "$result_path" ]]; then
  cp "$result_path" "${prefix}.proof.json"
fi

python3 - "$prefix" "$fs_mode" "$backend_mode" "$log_size" "$cap_mib" "$repetition" \
  "$status" "$start_ns" "$end_ns" "$result_path" <<'PY'
import json
import re
import sys
from pathlib import Path

prefix, fs_mode, backend_mode, log_size, cap, repetition, status, start, end, result_path = sys.argv[1:]
stderr = Path(prefix + ".stderr").read_text(encoding="utf-8", errors="replace")

def integer(label):
    match = re.search(rf"^\s*{re.escape(label)}:\s*(\d+)\s*$", stderr, re.MULTILINE)
    return int(match.group(1)) if match else None

proof = None
proof_copy = Path(prefix + ".proof.json")
if int(status) == 0 and proof_copy.exists():
    proof = json.loads(proof_copy.read_text(encoding="utf-8"))

store_rows = []
store_path = Path(prefix + ".store.jsonl")
if store_path.exists():
    store_rows = [json.loads(line) for line in store_path.read_text().splitlines() if line]

failure_kind = None
if int(status) != 0:
    if "memory allocation of" in stderr and "failed" in stderr:
        failure_kind = "allocator_rejection"
    elif re.search(r"\bKilled\b", stderr):
        failure_kind = "os_or_cgroup_kill"
    elif "panicked at" in stderr:
        failure_kind = "panic"
    else:
        failure_kind = "nonzero_exit"

payload = {
    "fs_mode": fs_mode,
    "backend_mode": backend_mode,
    "log_size": int(log_size),
    "relation_size": 1 << int(log_size),
    "cap_mib": None if cap == "uncapped" else int(cap),
    "repetition": int(repetition),
    "exit_status": int(status),
    "completed": int(status) == 0,
    "failure_kind": failure_kind,
    "wall_clock_ms": (int(end) - int(start)) / 1_000_000,
    "peak_rss_kib": integer("Maximum resident set size (kbytes)"),
    "major_page_faults": integer("Major (requiring I/O) page faults"),
    "minor_page_faults": integer("Minor (reclaiming a frame) page faults"),
    "proof": proof,
    "state_store": store_rows,
    "temporary_state_cleanup_by_parent": True,
}
Path(prefix + ".json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print(json.dumps({
    "fs_mode": fs_mode,
    "log_size": int(log_size),
    "cap_mib": payload["cap_mib"],
    "repetition": int(repetition),
    "exit_status": int(status),
    "completed": payload["completed"],
    "failure_kind": failure_kind,
    "wall_clock_ms": payload["wall_clock_ms"],
    "peak_rss_kib": payload["peak_rss_kib"],
    "proof_sha256": proof.get("proof_sha256") if proof else None,
    "upstream_verifier_accepts": proof.get("original_upstream_verifier_accepts") if proof else None,
    "state_store": store_rows,
}, separators=(",", ":")))
PY

exit 0
