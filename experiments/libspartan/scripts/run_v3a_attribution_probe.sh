#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."
mkdir -p results/v3a_probe

runner="$PWD/target/release/phase_v2_pbmo"
if [[ ! -x "$runner" ]]; then
  echo "missing release runner: $runner" >&2
  exit 2
fi

mode="${1:-native}"
log_size="${2:-18}"
shift "$(( $# >= 2 ? 2 : $# ))"
caps=("${@:-512 768 1024 uncapped}")
trace_min_bytes="${V3A_TRACE_MIN_BYTES:-65536}"

for cap in ${caps[*]}; do
  prefix="results/v3a_probe/${mode}_${log_size}_${cap}"
  trace="${prefix}_trace.jsonl"
  rm -f "$trace"
  start_ns=$(date +%s%N)
  if [[ "$cap" == "uncapped" ]]; then
    V3A_MEMORY_TRACE_PATH="$trace" V3A_MEMORY_TRACE_MIN_BYTES="$trace_min_bytes" \
      /usr/bin/time -v "$runner" "$mode" "$log_size" \
      >"${prefix}.stdout" 2>"${prefix}.stderr"
  else
    (
      ulimit -v "$((cap * 1024))"
      V3A_MEMORY_TRACE_PATH="$trace" V3A_MEMORY_TRACE_MIN_BYTES="$trace_min_bytes" \
        /usr/bin/time -v "$runner" "$mode" "$log_size"
    ) >"${prefix}.stdout" 2>"${prefix}.stderr"
  fi
  status=$?
  end_ns=$(date +%s%N)
  printf '%s\n' "$status" >"${prefix}.exit"
  printf 'cap=%s mode=%s log_size=%s status=%s elapsed_ms=%s\n' \
    "$cap" "$mode" "$log_size" "$status" "$(((end_ns - start_ns) / 1000000))"
  if [[ -f "$trace" ]]; then
    tail -n 1 "$trace"
  fi
done
