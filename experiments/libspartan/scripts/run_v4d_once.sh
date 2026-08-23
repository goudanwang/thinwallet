#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

workload="${1:?expected W1-W4, S-W1..S-W4, or S-WK-k-d}"
experiment="${2:?expected E0, E1, E2, E3, E4, B0, or B1}"
log_size="${3:?expected log size}"
cap_mib="${4:-uncapped}"
repetition="${5:-1}"

case "$workload" in W1|W2|W3|W4|S-W1|S-W2|S-W3|S-W4|S-WK-*) ;; *) exit 2 ;; esac
case "$experiment" in E0|E1|E2|E3|E4|B0|B1) ;; *) exit 2 ;; esac

runner="$PWD/target/release/phase_v2_pbmo"
out_dir="$PWD/../credential_workloads/results/v4d/runs"
safe_workload="${workload//-/_}"
session="v4d-${safe_workload}-${experiment}-${cap_mib}-${repetition}-$$"
state_root="/tmp/thinwallet-$session"
prefix="$out_dir/${safe_workload}_${experiment}_${cap_mib}_r${repetition}"
mkdir -p "$out_dir" "$state_root/v3a" "$state_root/v3b"

cleanup() {
  case "$state_root" in
    /tmp/thinwallet-v4d-*) find "$state_root" -type f -delete 2>/dev/null || true
      find "$state_root" -depth -type d -empty -delete 2>/dev/null || true ;;
  esac
}
trap cleanup EXIT INT TERM

case "$experiment" in
  E0) command=native; streaming=0; provider=native ;;
  B0) command=upstream; streaming=0; provider=upstream ;;
  B1) command=native; streaming=0; provider=native ;;
  E1) command=plain; streaming=0; provider=plain ;;
  E2) command=malicious; streaming=0; provider=malicious ;;
  E3) command=semi; streaming=1; provider=semi ;;
  E4) command=malicious; streaming=1; provider=malicious ;;
esac

if [[ "$cap_mib" == uncapped ]]; then
  hard_limit_bytes="$((8 * 1024 * 1024 * 1024))"
else
  hard_limit_bytes="$((cap_mib * 1024 * 1024))"
fi

run_backend() {
  local -a trace_env=()
  if [[ "${V4B_TRACE_TRANSCRIPT:-0}" == 1 ]]; then
    trace_env=(V3A_TRANSCRIPT_TRACE_PATH="${prefix}.transcript.jsonl")
  fi
  env \
    "${trace_env[@]}" \
    THINWALLET_CREDENTIAL_WORKLOAD="$workload" \
    LIBSPARTAN_FIXED_STREAMING="$streaming" \
    LIBSPARTAN_MULTI_TARGET_STREAMING="$streaming" \
    LIBSPARTAN_ACTIVE_STATE_STREAMING="$streaming" \
    LIBSPARTAN_TRANSCRIPT_RECOMPUTE="$streaming" \
    LIBSPARTAN_STREAMING_DEREFERENCE="$streaming" \
    LIBSPARTAN_CREDENTIAL_STREAMING="${V4D_FS7:-1}" \
    LIBSPARTAN_EPHEMERAL_STATE=1 \
    RAYON_NUM_THREADS=1 \
    V3A_STATE_DIR="$state_root/v3a" \
    V3A_STATE_SESSION="$session" \
    V3A_STATE_REPORT_PATH="${prefix}.v3a-store.jsonl" \
    V3B_STATE_DIR="$state_root/v3b" \
    V3B_STATE_SESSION="$session" \
    V3B_STATE_REPORT_PATH="${prefix}.v3b-store.json" \
    V3B_PLAN_REPORT_PATH="${prefix}.plan.json" \
    V3B_HARD_LIMIT_BYTES="$hard_limit_bytes" \
    V3B_RESERVED_RUNTIME_BYTES="${V4D_RUNTIME_RESERVE_BYTES:-$((4208 * 1024))}" \
    THINWALLET_DEFER_UPSTREAM_VERIFY=1 \
    THINWALLET_PROOF_OUT="${prefix}.proof.bin" \
    THINWALLET_RESULT_OUT="${prefix}.proof.json" \
    /usr/bin/time -v "$runner" "$command" "$log_size"
}

start_ns=$(date +%s%N)
set +e
external_verify_status=null
external_verify_ms=null
if [[ "$workload" == S-* ]]; then
  external_start_ns=$(date +%s%N)
  "$PWD/target/release/phase_v4c_profile_s" verify-fixture >"${prefix}.external-auth.json" 2>"${prefix}.external-auth.stderr"
  external_verify_status=$?
  external_end_ns=$(date +%s%N)
  external_verify_ms=$(python3 -c "print(($external_end_ns-$external_start_ns)/1e6)")
fi
if [[ "$external_verify_status" != null && "$external_verify_status" -ne 0 ]]; then
  status=$external_verify_status
elif [[ "$cap_mib" == uncapped || "${V4D_CGROUP_ENFORCED:-0}" == 1 ]]; then
  run_backend >"${prefix}.stdout" 2>"${prefix}.stderr"
  status=$?
else
  (ulimit -v "$((cap_mib * 1024))"; run_backend) >"${prefix}.stdout" 2>"${prefix}.stderr"
  status=$?
fi
set -e
end_ns=$(date +%s%N)

verify_status=null
if [[ $status -eq 0 && "${V4D_DEFER_EXTERNAL_VERIFY:-0}" != 1 ]]; then
  set +e
  env THINWALLET_CREDENTIAL_WORKLOAD="$workload" \
    "$runner" verify-proof "${prefix}.proof.bin" "$log_size" \
    >"${prefix}.verify.json" 2>"${prefix}.verify.stderr"
  verify_status=$?
  set -e
fi

python3 - "$prefix" "$workload" "$experiment" "$provider" "$log_size" "$cap_mib" "$repetition" "$status" "$start_ns" "$end_ns" "$verify_status" "$external_verify_status" "$external_verify_ms" <<'PY'
import hashlib, json, os, re, sys
from pathlib import Path

prefix, workload, experiment, provider, logn, cap, rep, status, start, end, verify_status, external_status, external_ms = sys.argv[1:]
stderr_path = Path(prefix + ".stderr")
stderr = stderr_path.read_text(errors="replace") if stderr_path.exists() else ""
def timed(label):
    match = re.search(rf"^\s*{re.escape(label)}:\s*([0-9.]+)\s*$", stderr, re.M)
    return float(match.group(1)) if match else None
def load(suffix):
    path = Path(prefix + suffix)
    return json.loads(path.read_text()) if path.exists() else None
proof = Path(prefix + ".proof.bin")
trace = Path(prefix + ".transcript.jsonl")
verify = load(".verify.json")
failure = None
if int(status):
    if "controlled plan rejection" in stderr: failure = "controlled_budget_rejection"
    elif "memory allocation of" in stderr: failure = "allocator_failure"
    elif re.search(r"\bKilled\b", stderr): failure = "oom_killed"
    elif "panicked at" in stderr: failure = "panic"
    else: failure = "nonzero_exit"
data = {
    "workload": workload, "experiment": experiment, "provider": provider,
    "log_size": int(logn), "padded_size": 1 << int(logn),
    "cap_mib": None if cap == "uncapped" else int(cap), "repetition": int(rep),
    "exit_status": int(status), "completed": int(status) == 0, "failure_kind": failure,
    "wall_clock_ms": (int(end) - int(start)) / 1e6,
    "user_cpu_seconds": timed("User time (seconds)"),
    "system_cpu_seconds": timed("System time (seconds)"),
    "peak_rss_kib": timed("Maximum resident set size (kbytes)"),
    "swaps": timed("Swaps"), "filesystem_inputs": timed("File system inputs"),
    "filesystem_outputs": timed("File system outputs"),
    "proof_sha256": hashlib.sha256(proof.read_bytes()).hexdigest() if proof.exists() else None,
    "proof_size_bytes": proof.stat().st_size if proof.exists() else None,
    "transcript_sha256": hashlib.sha256(trace.read_bytes()).hexdigest() if trace.exists() else None,
    "transcript_events": sum(1 for _ in trace.open()) if trace.exists() else None,
    "external_signature_verification_exit_status": None if external_status == "null" else int(external_status),
    "external_signature_verification_wall_ms": None if external_ms == "null" else float(external_ms),
    "patched_result": load(".proof.json"), "external_upstream_verifier": verify,
    "external_upstream_verifier_exit_status": None if verify_status == "null" else int(verify_status),
    "external_upstream_verifier_deferred": os.environ.get("V4D_DEFER_EXTERNAL_VERIFY") == "1",
    "state_store": load(".v3b-store.json"), "memory_plan": load(".plan.json"),
}
Path(prefix + ".json").write_text(json.dumps(data, indent=2) + "\n")
print(json.dumps({key: data[key] for key in ("workload", "experiment", "cap_mib", "exit_status", "wall_clock_ms", "peak_rss_kib", "proof_sha256")}, separators=(",", ":")))
PY

exit 0
