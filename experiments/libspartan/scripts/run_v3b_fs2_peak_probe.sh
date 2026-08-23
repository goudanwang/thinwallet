#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

log_size="${1:-18}"
shift "$(( $# >= 1 ? 1 : $# ))"
if [[ $# -eq 0 ]]; then
  caps=(896 1024 uncapped)
else
  caps=("$@")
fi
runner="$PWD/target/release/phase_v2_pbmo"
out_dir="$PWD/results/v3b_peak"
trace_min_bytes="${V3B_TRACE_MIN_BYTES:-65536}"

mkdir -p "$out_dir" "$PWD/results/v3b_state"
if [[ ! -x "$runner" ]]; then
  echo "missing release runner: $runner" >&2
  exit 2
fi

read_kib() {
  local file="$1" label="$2"
  awk -v label="$label" '$1 == label":" { print $2; found=1 } END { if (!found) print "null" }' "$file" 2>/dev/null
}

read_number() {
  local file="$1"
  if [[ -r "$file" ]]; then
    local value
    value=$(cat "$file" 2>/dev/null || true)
    if [[ "$value" =~ ^[0-9]+$ ]]; then printf '%s' "$value"; else printf 'null'; fi
  else
    printf 'null'
  fi
}

for cap in "${caps[@]}"; do
  session="fs2-${log_size}-${cap}"
  prefix="$out_dir/FS2_${log_size}_${cap}"
  state_dir="$PWD/results/v3b_state/$session"
  trace="${prefix}.alloc.jsonl"
  samples="${prefix}.resident.jsonl"
  store_report="${prefix}.store.jsonl"
  stdout="${prefix}.stdout"
  stderr="${prefix}.stderr"
  rm -f "$trace" "$samples" "$store_report" "$stdout" "$stderr"
  mkdir -p "$state_dir"

  cleanup() {
    if [[ "$state_dir" == "$PWD/results/v3b_state/"* ]]; then
      find "$state_dir" -type f -delete 2>/dev/null || true
      rmdir "$state_dir" 2>/dev/null || true
    fi
  }
  trap cleanup EXIT INT TERM

  start_ns=$(date +%s%N)
  set +e
  (
    if [[ "$cap" != "uncapped" ]]; then
      ulimit -v "$((cap * 1024))"
    fi
    LIBSPARTAN_FIXED_STREAMING=1 \
      V3A_STATE_DIR="$state_dir" \
      V3A_STATE_SESSION="$session" \
      V3A_STATE_REPORT_PATH="$store_report" \
      V3A_MEMORY_TRACE_PATH="$trace" \
      V3A_MEMORY_TRACE_MIN_BYTES="$trace_min_bytes" \
      "$runner" semi "$log_size" >"$stdout" 2>"$stderr" &
    prover_pid=$!
    cgroup_rel=$(awk -F: '$1 == "0" { print $3 }' "/proc/$prover_pid/cgroup" 2>/dev/null)
    cgroup_dir="/sys/fs/cgroup${cgroup_rel:-/}"
    while kill -0 "$prover_pid" 2>/dev/null; do
      status_file="/proc/$prover_pid/status"
      now_ns=$(date +%s%N)
      state_bytes=$(find "$state_dir" -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}')
      printf '{"timestamp_ns":%s,"vm_rss_kib":%s,"rss_anon_kib":%s,"rss_file_kib":%s,"vm_size_kib":%s,"vm_swap_kib":%s,"temporary_file_bytes":%s,"cgroup_memory_current_bytes":%s,"cgroup_memory_peak_bytes":%s}\n' \
        "$now_ns" \
        "$(read_kib "$status_file" VmRSS)" \
        "$(read_kib "$status_file" RssAnon)" \
        "$(read_kib "$status_file" RssFile)" \
        "$(read_kib "$status_file" VmSize)" \
        "$(read_kib "$status_file" VmSwap)" \
        "$state_bytes" \
        "$(read_number "$cgroup_dir/memory.current")" \
        "$(read_number "$cgroup_dir/memory.peak")" >>"$samples"
      sleep 0.02
    done
    wait "$prover_pid"
  )
  status=$?
  set -e
  end_ns=$(date +%s%N)

  printf '%s\n' "$status" >"${prefix}.exit"
  printf '{"mode":"FS2","log_size":%s,"cap_mib":%s,"exit_status":%s,"elapsed_ms":%s,"cache_profile":"write_then_read_warm_page_cache","cold_cache_attempted":false,"cold_cache_note":"privileged global cache eviction not permitted"}\n' \
    "$log_size" \
    "$([[ "$cap" == "uncapped" ]] && printf 'null' || printf '%s' "$cap")" \
    "$status" \
    "$(((end_ns - start_ns) / 1000000))" >"${prefix}.run.json"
  cat "${prefix}.run.json"
  cleanup
  trap - EXIT INT TERM
done
