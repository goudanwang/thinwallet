#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

monotonic_ns() {
  python3 -c 'import time; print(time.monotonic_ns())'
}

workload="${1:?expected canonical S-WK workload}"
mode="${2:?expected M0 through M4}"
log_size="${3:?expected relation log size}"
cap_mib="${4:-uncapped}"
repetition="${5:-1}"
tag="${6:-headline}"

case "$workload" in S-WK-*) ;; *) echo "V4F requires canonical S-WK workload" >&2; exit 2 ;; esac
case "$mode" in M0|M1|M2|M3|M4) ;; *) echo "unknown V4F mode" >&2; exit 2 ;; esac

case "$mode" in
  M0) command=native; provider=native; streaming=0 ;;
  M1) command=plain; provider=plain; streaming=0 ;;
  M2) command=malicious; provider=malicious; streaming=0 ;;
  M3) command=semi; provider=semi; streaming=1 ;;
  M4) command=malicious; provider=malicious; streaming=1 ;;
esac

runner="$PWD/target/release/phase_v2_pbmo"
out_dir="${THINWALLET_RESULTS_ROOT:-$PWD/../../results/v4f/raw/runs}"
safe_workload="${workload//-/_}"
session="v4f-${safe_workload}-${mode}-${cap_mib}-${repetition}-$$"
state_root="/tmp/thinwallet-$session"
prefix="$out_dir/${tag}_${safe_workload}_${mode}_${cap_mib}_r${repetition}"
source_path="$PWD/../credential_workloads/results/v4e/sources/${safe_workload}.twcs"
proof_session_id=$(python3 - "$workload" <<'PY'
import hashlib, sys
w = sys.argv[1].replace("sparse-merkle", "sparse_merkle").replace("expiry-only", "expiry_only").encode()
generation = (1).to_bytes(8, "big")
h = hashlib.sha256(b"thinwallet/proof-session/v1")
for value in (w, generation):
    h.update(len(value).to_bytes(8, "big")); h.update(value)
print(h.hexdigest())
PY
)

mkdir -p "$out_dir" "$state_root/v3a" "$state_root/v3b"
find "$out_dir" -maxdepth 1 -type f -name "$(basename "$prefix").*" -delete
if [[ ! -x "$runner" || ! -f "$source_path" ]]; then
  echo "missing runner or authenticated source fixture" >&2
  printf '127\n' >"${prefix}.exit_status"
  exit 0
fi

cleanup() {
  case "$state_root" in
    /tmp/thinwallet-v4f-*) find "$state_root" -type f -delete 2>/dev/null || true
      find "$state_root" -depth -type d -empty -delete 2>/dev/null || true ;;
  esac
}
trap cleanup EXIT INT TERM

if [[ "$cap_mib" == uncapped ]]; then
  hard_limit_bytes=$((8 * 1024 * 1024 * 1024))
else
  hard_limit_bytes=$((cap_mib * 1024 * 1024))
fi

run_backend() {
  local -a trace_env=()
  if [[ "${V4F_TRACE_TRANSCRIPT:-0}" == 1 ]]; then
    trace_env=(V3A_TRANSCRIPT_TRACE_PATH="${prefix}.transcript.jsonl")
  fi
  env \
    "${trace_env[@]}" \
    THINWALLET_CREDENTIAL_WORKLOAD="$workload" \
    THINWALLET_CREDENTIAL_SOURCE_PATH="$source_path" \
    THINWALLET_PROOF_SESSION_ID="$proof_session_id" \
    LIBSPARTAN_FIXED_STREAMING="$streaming" \
    LIBSPARTAN_MULTI_TARGET_STREAMING="$streaming" \
    LIBSPARTAN_ACTIVE_STATE_STREAMING="$streaming" \
    LIBSPARTAN_TRANSCRIPT_RECOMPUTE="$streaming" \
    LIBSPARTAN_STREAMING_DEREFERENCE="$streaming" \
    LIBSPARTAN_CREDENTIAL_STREAMING="$streaming" \
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
    V3B_RESERVED_RUNTIME_BYTES=$((4208 * 1024)) \
    THINWALLET_DEFER_UPSTREAM_VERIFY=1 \
    THINWALLET_PROOF_OUT="${prefix}.proof.bin" \
    THINWALLET_RESULT_OUT="${prefix}.proof.json" \
    /usr/bin/time -v "$runner" "$command" "$log_size"
}

start_ns=$(monotonic_ns)
set +e
external_start_ns=$(monotonic_ns)
"$PWD/target/release/phase_v4c_profile_s" verify-fixture \
  >"${prefix}.external-auth.json" 2>"${prefix}.external-auth.stderr"
external_status=$?
external_end_ns=$(monotonic_ns)
external_ms=$(python3 -c "print(($external_end_ns-$external_start_ns)/1e6)")

if [[ $external_status -ne 0 ]]; then
  status=$external_status
elif [[ "$cap_mib" == uncapped || "${V4F_CGROUP_ENFORCED:-0}" == 1 ]]; then
  run_backend >"${prefix}.stdout" 2>"${prefix}.stderr"
  status=$?
else
  (ulimit -v "$((cap_mib * 1024))"; run_backend) >"${prefix}.stdout" 2>"${prefix}.stderr"
  status=$?
fi
set -e
end_ns=$(monotonic_ns)
wall_ms=$(python3 -c "print(($end_ns-$start_ns)/1e6)")
printf '%s\n' "$status" >"${prefix}.exit_status"
printf '%s\n' "$wall_ms" >"${prefix}.wall_ms"
printf '%s\n' "$external_status" >"${prefix}.external_auth_status"
printf '%s\n' "$external_ms" >"${prefix}.external_auth_ms"

verify_status=null
verify_ms=null
if [[ $status -eq 0 && "${V4F_DEFER_EXTERNAL_VERIFY:-0}" != 1 ]]; then
  verify_start_ns=$(monotonic_ns)
  set +e
  env THINWALLET_CREDENTIAL_WORKLOAD="$workload" \
    THINWALLET_CREDENTIAL_SOURCE_PATH="$source_path" \
    THINWALLET_PROOF_SESSION_ID="$proof_session_id" \
    "$runner" verify-proof "${prefix}.proof.bin" "$log_size" \
    >"${prefix}.verify.json" 2>"${prefix}.verify.stderr"
  verify_status=$?
  set -e
  verify_end_ns=$(monotonic_ns)
  verify_ms=$(python3 -c "print(($verify_end_ns-$verify_start_ns)/1e6)")
fi
printf '%s\n' "$verify_status" >"${prefix}.verify_status"
printf '%s\n' "$verify_ms" >"${prefix}.verify_ms"

if [[ "${V4F_DEFER_COLLECT:-0}" != 1 ]]; then
  python3 "$PWD/scripts/collect_v4f_run.py" "$prefix" "$workload" "$mode" \
    "$log_size" "$cap_mib" "$repetition" "$status" "$wall_ms" \
    "$external_status" "$external_ms" "$verify_status" "$verify_ms"
fi

exit 0
