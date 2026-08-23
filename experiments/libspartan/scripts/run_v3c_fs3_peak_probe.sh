#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

runner="$PWD/target/release/phase_v2_pbmo"
out_dir="$PWD/results/v3c_peak"
trace_min_bytes="${V3C_TRACE_MIN_BYTES:-65536}"
mkdir -p "$out_dir" "$PWD/results/v3c_state"

if [[ ! -x "$runner" ]]; then
  echo "missing release runner: $runner" >&2
  exit 2
fi

read_kib() {
  local file="$1" label="$2"
  awk -v label="$label" '$1 == label":" { print $2; found=1 } END { if (!found) print "null" }' "$file" 2>/dev/null
}

for cap in 512 640 uncapped; do
  session="v3c-fs3-18-$cap"
  prefix="$out_dir/FS3_18_$cap"
  state_dir="$PWD/results/v3c_state/$session"
  trace="${prefix}.alloc.jsonl"
  resident="${prefix}.resident.jsonl"
  store_report="${prefix}.store.json"
  plan_report="${prefix}.plan.json"
  mkdir -p "$state_dir"
  rm -f "$trace" "$resident" "$store_report" "$plan_report" \
    "${prefix}.stdout" "${prefix}.stderr" "${prefix}.exit" "${prefix}.run.json"

  start_ns=$(date +%s%N)
  set +e
  (
    if [[ "$cap" != uncapped ]]; then
      ulimit -v "$((cap * 1024))"
    fi
    LIBSPARTAN_FIXED_STREAMING=1 \
      LIBSPARTAN_MULTI_TARGET_STREAMING=1 \
      V3A_STATE_DIR="$state_dir/v3a" \
      V3A_STATE_SESSION="$session" \
      V3B_STATE_DIR="$state_dir/v3b" \
      V3B_STATE_SESSION="$session" \
      V3B_STATE_REPORT_PATH="$store_report" \
      V3B_PLAN_REPORT_PATH="$plan_report" \
      V3B_HARD_LIMIT_BYTES="$([[ "$cap" == uncapped ]] && echo $((2048 * 1024 * 1024)) || echo $((cap * 1024 * 1024)))" \
      V3B_RESERVED_RUNTIME_BYTES="$((111 * 1024 * 1024))" \
      V3A_MEMORY_TRACE_PATH="$trace" \
      V3A_MEMORY_TRACE_MIN_BYTES="$trace_min_bytes" \
      "$runner" semi 18 >"${prefix}.stdout" 2>"${prefix}.stderr" &
    prover_pid=$!
    while kill -0 "$prover_pid" 2>/dev/null; do
      status_file="/proc/$prover_pid/status"
      state_bytes=$(find "$state_dir" -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}')
      printf '{"timestamp_epoch_ns":%s,"vm_rss_kib":%s,"vm_hwm_kib":%s,"rss_anon_kib":%s,"rss_file_kib":%s,"vm_size_kib":%s,"vm_swap_kib":%s,"temporary_file_bytes":%s}\n' \
        "$(date +%s%N)" \
        "$(read_kib "$status_file" VmRSS)" \
        "$(read_kib "$status_file" VmHWM)" \
        "$(read_kib "$status_file" RssAnon)" \
        "$(read_kib "$status_file" RssFile)" \
        "$(read_kib "$status_file" VmSize)" \
        "$(read_kib "$status_file" VmSwap)" \
        "$state_bytes" >>"$resident"
      sleep 0.02
    done
    wait "$prover_pid"
  )
  status=$?
  set -e
  end_ns=$(date +%s%N)

  printf '%s\n' "$status" >"${prefix}.exit"
  printf '{"mode":"FS3","log_size":18,"cap_mib":%s,"exit_status":%s,"elapsed_ms":%s,"trace_minimum_bytes":%s}\n' \
    "$([[ "$cap" == uncapped ]] && echo null || echo "$cap")" "$status" \
    "$(((end_ns - start_ns) / 1000000))" "$trace_min_bytes" >"${prefix}.run.json"
  cat "${prefix}.run.json"

  if [[ "$state_dir" == "$PWD/results/v3c_state/"* ]]; then
    find "$state_dir" -type f -delete 2>/dev/null || true
    find "$state_dir" -depth -type d -empty -delete 2>/dev/null || true
  fi
done

