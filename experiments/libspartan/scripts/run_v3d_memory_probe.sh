#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."
mode="${1:?expected FS4, FS5, or FS6}"
case "$mode" in
  FS4) recompute=0; ephemeral=0; fs6=0 ;;
  FS5) recompute=1; ephemeral=1; fs6=0 ;;
  FS6) recompute=1; ephemeral=1; fs6=1 ;;
  *) echo "invalid mode: $mode" >&2; exit 2 ;;
esac

runner="$PWD/target/release/phase_v2_pbmo"
out_dir="$PWD/results/v3d_memory"
session="v3d-${mode,,}-probe-$$"
state_root="/tmp/thinwallet-$session"
prefix="$out_dir/${mode}_18_uncapped"
samples="${prefix}.smaps.jsonl"
mkdir -p "$out_dir" "$state_root/v3a" "$state_root/v3b"
rm -f "$samples" "${prefix}."{stdout,stderr,store.json,plan.json,proof.bin,result.json,exit}

cleanup() {
  case "$state_root" in
    /tmp/thinwallet-v3d-*) find "$state_root" -type f -delete 2>/dev/null || true
      find "$state_root" -depth -type d -empty -delete 2>/dev/null || true ;;
  esac
}
trap cleanup EXIT INT TERM

read_field() {
  local file="$1" field="$2"
  awk -v field="$field" '$1 == field":" {print $2; found=1} END {if (!found) print "null"}' "$file" 2>/dev/null
}

env \
  LIBSPARTAN_FIXED_STREAMING=1 \
  LIBSPARTAN_MULTI_TARGET_STREAMING=1 \
  LIBSPARTAN_ACTIVE_STATE_STREAMING=1 \
  LIBSPARTAN_TRANSCRIPT_RECOMPUTE="$recompute" \
  LIBSPARTAN_STREAMING_DEREFERENCE="$fs6" \
  LIBSPARTAN_EPHEMERAL_STATE="$ephemeral" \
  RAYON_NUM_THREADS=1 \
  V3A_STATE_DIR="$state_root/v3a" \
  V3A_STATE_SESSION="$session" \
  V3B_STATE_DIR="$state_root/v3b" \
  V3B_STATE_SESSION="$session" \
  V3B_STATE_REPORT_PATH="${prefix}.store.json" \
  V3B_PLAN_REPORT_PATH="${prefix}.plan.json" \
  V3B_HARD_LIMIT_BYTES="$((8 * 1024 * 1024 * 1024))" \
  V3B_RESERVED_RUNTIME_BYTES="$((111 * 1024 * 1024))" \
  THINWALLET_DEFER_UPSTREAM_VERIFY=1 \
  THINWALLET_PROOF_OUT="${prefix}.proof.bin" \
  THINWALLET_RESULT_OUT="${prefix}.result.json" \
  "$runner" malicious 18 >"${prefix}.stdout" 2>"${prefix}.stderr" &
pid=$!

while kill -0 "$pid" 2>/dev/null; do
  status="/proc/$pid/status"
  rollup="/proc/$pid/smaps_rollup"
  temporary=$(find "$state_root" -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}')
  stack_reserved=$(awk '/\[stack/ {split($1,a,"-"); s += strtonum("0x" a[2])-strtonum("0x" a[1])} END {print s+0}' "/proc/$pid/maps" 2>/dev/null)
  printf '{"timestamp_epoch_ns":%s,"vm_rss_kib":%s,"vm_hwm_kib":%s,"rss_anon_kib":%s,"rss_file_kib":%s,"vm_data_kib":%s,"vm_stk_kib":%s,"vm_size_kib":%s,"vm_swap_kib":%s,"pss_kib":%s,"pss_anon_kib":%s,"pss_file_kib":%s,"private_dirty_kib":%s,"threads":%s,"stack_reserved_bytes":%s,"temporary_file_bytes":%s}\n' \
    "$(date +%s%N)" \
    "$(read_field "$status" VmRSS)" \
    "$(read_field "$status" VmHWM)" \
    "$(read_field "$status" RssAnon)" \
    "$(read_field "$status" RssFile)" \
    "$(read_field "$status" VmData)" \
    "$(read_field "$status" VmStk)" \
    "$(read_field "$status" VmSize)" \
    "$(read_field "$status" VmSwap)" \
    "$(read_field "$rollup" Pss)" \
    "$(read_field "$rollup" Pss_Anon)" \
    "$(read_field "$rollup" Pss_File)" \
    "$(read_field "$rollup" Private_Dirty)" \
    "$(read_field "$status" Threads)" \
    "$stack_reserved" \
    "$temporary" >>"$samples"
  sleep 0.02
done
wait "$pid"
status=$?
printf '%s\n' "$status" >"${prefix}.exit"
python3 - "$mode" "$samples" "$status" "${prefix}.summary.json" <<'PY'
import json
import sys
from pathlib import Path

mode, samples_path, status, output_path = sys.argv[1:]
samples = []
invalid_samples = 0
for line in Path(samples_path).read_text().splitlines():
    if not line:
        continue
    try:
        samples.append(json.loads(line))
    except json.JSONDecodeError:
        invalid_samples += 1
peak = max(samples, key=lambda item: item.get("vm_rss_kib") or -1)
summary = {
    "mode": mode,
    "log_size": 18,
    "exit_status": int(status),
    "sample_count": len(samples),
    "invalid_samples": invalid_samples,
    "peak_sample": peak,
    "max_pss_kib": max((item.get("pss_kib") or 0) for item in samples),
    "max_rss_anon_kib": max((item.get("rss_anon_kib") or 0) for item in samples),
    "max_rss_file_kib": max((item.get("rss_file_kib") or 0) for item in samples),
    "max_threads": max((item.get("threads") or 0) for item in samples),
    "max_stack_reserved_bytes": max((item.get("stack_reserved_bytes") or 0) for item in samples),
    "max_temporary_file_bytes": max((item.get("temporary_file_bytes") or 0) for item in samples),
}
Path(output_path).write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, separators=(",", ":")))
PY

exit 0
