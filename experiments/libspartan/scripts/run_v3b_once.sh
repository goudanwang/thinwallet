#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

fs_mode="${1:?expected FS0, FS1, FS2, or FS3}"
log_size="${2:?expected log size}"
cap_mib="${3:?expected cap MiB or uncapped}"
repetition="${4:-1}"

case "$fs_mode" in
  FS0) backend_mode=upstream ;;
  FS1|FS2|FS3) backend_mode=semi ;;
  *) echo "invalid mode: $fs_mode" >&2; exit 2 ;;
esac

runner="$PWD/target/release/phase_v2_pbmo"
out_dir="$PWD/results/v3b_boundary"
session="${fs_mode}-${log_size}-${cap_mib}-${repetition}"
v3a_state="$PWD/results/v3b_state/v3a-$session"
v3b_state="$PWD/results/v3b_state/fs3-$session"
prefix="$out_dir/${fs_mode}_${log_size}_${cap_mib}_r${repetition}"
mkdir -p "$out_dir" "$v3a_state" "$v3b_state"
rm -f "${prefix}.stdout" "${prefix}.stderr" "${prefix}.v3a-store.jsonl" \
  "${prefix}.v3b-store.json" "${prefix}.plan.json" "${prefix}.json" "${prefix}.proof.json"

cleanup() {
  for dir in "$v3a_state" "$v3b_state"; do
    if [[ "$dir" == "$PWD/results/v3b_state/"* ]]; then
      find "$dir" -type f -delete 2>/dev/null || true
      find "$dir" -depth -type d -empty -delete 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT INT TERM

run_backend() {
  case "$fs_mode" in
    FS2)
      LIBSPARTAN_FIXED_STREAMING=1 \
        V3A_STATE_DIR="$v3a_state" V3A_STATE_SESSION="$session" \
        V3A_STATE_REPORT_PATH="${prefix}.v3a-store.jsonl" \
        /usr/bin/time -v "$runner" "$backend_mode" "$log_size"
      ;;
    FS3)
      LIBSPARTAN_FIXED_STREAMING=1 LIBSPARTAN_MULTI_TARGET_STREAMING=1 \
        V3A_STATE_DIR="$v3a_state" V3A_STATE_SESSION="$session" \
        V3A_STATE_REPORT_PATH="${prefix}.v3a-store.jsonl" \
        V3B_STATE_DIR="$v3b_state" V3B_STATE_SESSION="$session" \
        V3B_STATE_REPORT_PATH="${prefix}.v3b-store.json" \
        V3B_PLAN_REPORT_PATH="${prefix}.plan.json" \
        V3B_HARD_LIMIT_BYTES="$((cap_mib * 1024 * 1024))" \
        V3B_RESERVED_RUNTIME_BYTES="$((111 * 1024 * 1024))" \
        /usr/bin/time -v "$runner" "$backend_mode" "$log_size"
      ;;
    *) /usr/bin/time -v "$runner" "$backend_mode" "$log_size" ;;
  esac
}

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

result_path="results/v2_${log_size}_${backend_mode}.json"
if [[ $status -eq 0 && -f "$result_path" ]]; then
  cp "$result_path" "${prefix}.proof.json"
fi

python3 - "$prefix" "$fs_mode" "$backend_mode" "$log_size" "$cap_mib" \
  "$repetition" "$status" "$start_ns" "$end_ns" <<'PY'
import json, re, sys
from pathlib import Path

prefix, mode, backend, logn, cap, rep, status, start, end = sys.argv[1:]
stderr = Path(prefix + ".stderr").read_text(errors="replace")
def timed(label):
    m = re.search(rf"^\s*{re.escape(label)}:\s*(\d+)\s*$", stderr, re.M)
    return int(m.group(1)) if m else None
proof_path = Path(prefix + ".proof.json")
proof = json.loads(proof_path.read_text()) if proof_path.exists() else None
v3a_path = Path(prefix + ".v3a-store.jsonl")
v3a = [json.loads(line) for line in v3a_path.read_text().splitlines() if line] if v3a_path.exists() else []
v3b_path = Path(prefix + ".v3b-store.json")
v3b = json.loads(v3b_path.read_text()) if v3b_path.exists() else None
plan_path = Path(prefix + ".plan.json")
plan = json.loads(plan_path.read_text()) if plan_path.exists() else None
failure = None
if int(status):
    if "controlled budget rejection" in stderr or "controlled plan rejection" in stderr:
        failure = "controlled_budget_rejection"
    elif "memory allocation of" in stderr: failure = "allocator_failure"
    elif re.search(r"\bKilled\b", stderr): failure = "oom_killed"
    elif "panicked at" in stderr: failure = "panic"
    else: failure = "nonzero_exit"
data = {
    "fs_mode": mode, "backend_mode": backend, "log_size": int(logn),
    "relation_size": 1 << int(logn), "cap_mib": None if cap == "uncapped" else int(cap),
    "repetition": int(rep), "exit_status": int(status), "completed": int(status) == 0,
    "failure_kind": failure, "wall_clock_ms": (int(end)-int(start))/1e6,
    "peak_rss_kib": timed("Maximum resident set size (kbytes)"),
    "major_page_faults": timed("Major (requiring I/O) page faults"),
    "minor_page_faults": timed("Minor (reclaiming a frame) page faults"),
    "proof": proof, "v3a_state_store": v3a, "v3b_state_store": v3b, "memory_plan": plan,
    "swap_observed": False,
}
Path(prefix + ".json").write_text(json.dumps(data, indent=2) + "\n")
print(json.dumps({k: data[k] for k in (
    "fs_mode", "log_size", "cap_mib", "repetition", "exit_status", "completed",
    "failure_kind", "wall_clock_ms", "peak_rss_kib")}, separators=(",", ":")))
PY

exit 0
