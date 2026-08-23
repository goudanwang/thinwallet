#!/usr/bin/env bash
set -u

cd "$(dirname "$0")/.."
mkdir -p results/memory_caps

runner="$PWD/target/release/phase_v2_pbmo"
if [[ ! -x "$runner" ]]; then
  echo "missing release runner: $runner" >&2
  exit 2
fi

for cap in 128 256 512; do
  cap_kib=$((cap * 1024))
  for mode in native plain semi; do
    found=0
    for log_size in 18 16 14 12; do
      prefix="results/memory_caps/cap_${cap}_${mode}_${log_size}"
      start_ns=$(date +%s%N)
      (
        ulimit -v "$cap_kib"
        /usr/bin/time -v "$runner" "$mode" "$log_size"
      ) >"${prefix}.stdout" 2>"${prefix}.stderr"
      status=$?
      end_ns=$(date +%s%N)
      elapsed_ms=$(((end_ns - start_ns) / 1000000))
      peak_kib=$(awk -F: '/Maximum resident set size/ {gsub(/^[[:space:]]+/, "", $2); print $2}' "${prefix}.stderr" | tail -1)
      if [[ -z "$peak_kib" ]]; then
        peak_json=null
      else
        peak_json=$(awk -v kib="$peak_kib" 'BEGIN {printf "%.6f", kib / 1024.0}')
      fi
      oom=false
      if grep -Eqi 'cannot allocate memory|memory allocation.*failed|out of memory|killed' "${prefix}.stderr"; then
        oom=true
      fi
      cat >"${prefix}.json" <<EOF
{
  "cap_mib": $cap,
  "mode": "$mode",
  "log_size": $log_size,
  "relation_size": $((1 << log_size)),
  "exit_status": $status,
  "completed": $([[ $status -eq 0 ]] && echo true || echo false),
  "oom_or_allocation_failure": $oom,
  "peak_rss_mb": $peak_json,
  "latency_ms": $elapsed_ms,
  "token_storage_mode": "file-backed token; correction vector decoded in memory",
  "classification": "PRELIMINARY_MEMORY_CAP_SMOKE_TEST_ONLY"
}
EOF
      if [[ $status -eq 0 ]]; then
        found=1
        break
      fi
    done
    if [[ $found -eq 0 ]]; then
      echo "no feasible workload for cap=$cap mode=$mode" >&2
    fi
  done
done

python3 - <<'PY'
import glob
import json
from pathlib import Path

attempts = []
for path in sorted(glob.glob("results/memory_caps/cap_*.json")):
    with open(path, encoding="utf-8") as handle:
        attempts.append(json.load(handle))

largest = []
for cap in (128, 256, 512):
    for mode in ("native", "plain", "semi"):
        completed = [
            item for item in attempts
            if item["cap_mib"] == cap and item["mode"] == mode and item["completed"]
        ]
        largest.append({
            "cap_mib": cap,
            "mode": mode,
            "largest_completed_log_size": max((item["log_size"] for item in completed), default=None),
            "largest_completed_relation_size": max((item["relation_size"] for item in completed), default=None),
        })

summary = {
    "status": "PREPROCESSED_PBMO_MEMORY_CAP_SMOKE_TEST_COMPLETE",
    "mobile_feasibility_claim": False,
    "attempts": attempts,
    "largest_feasible": largest,
}
Path("results/phase_v2_memory_caps.json").write_text(
    json.dumps(summary, indent=2) + "\n", encoding="utf-8"
)
PY

echo PREPROCESSED_PBMO_MEMORY_CAP_SMOKE_TEST_COMPLETE
