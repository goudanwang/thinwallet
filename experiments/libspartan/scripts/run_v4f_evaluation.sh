#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
phase="${1:-all}"
caps=(64 96 128 192 224 256)
out="$PWD/../../results/v4f/raw/runs"
mkdir -p "$out"

declare -A WORKLOADS=(
  [H0]="S-WK-k8-r0-d0-none 16"
  [H1]="S-WK-k52-r1-d32-sparse_merkle 18"
  [H2]="S-WK-k8-r8-d32-sparse_merkle 18"
)

run_direct() {
  local workload=$1 mode=$2 logn=$3 rep=$4 tag=$5 trace=${6:-0}
  local safe=${workload//-/_}
  [[ -s "$out/${tag}_${safe}_${mode}_uncapped_r${rep}.json" ]] && return
  runuser -u ubuntu -- env V4F_TRACE_TRANSCRIPT="$trace" \
    "$PWD/scripts/run_v4f_once.sh" "$workload" "$mode" "$logn" uncapped "$rep" "$tag"
}

run_cap() {
  local workload=$1 mode=$2 logn=$3 cap=$4 rep=$5 tag=$6 trace=${7:-0}
  local safe=${workload//-/_}
  [[ -s "$out/${tag}_${safe}_${mode}_${cap}_r${rep}.json" ]] && return
  V4F_TRACE_TRANSCRIPT="$trace" "$PWD/scripts/run_v4f_cgroup_once.sh" \
    "$workload" "$mode" "$logn" "$cap" "$rep" "$tag"
}

minimum_cap() {
  local workload=$1 mode=$2 tag=$3 safe=${workload//-/_}
  python3 - "$out" "$tag" "$safe" "$mode" <<'PY'
import json, sys
from pathlib import Path
root, tag, workload, mode = Path(sys.argv[1]), *sys.argv[2:]
passing=[]
for path in root.glob(f"{tag}_{workload}_{mode}_*_r1.json"):
    data=json.loads(path.read_text())
    if data.get("cap_mib") is not None and data.get("result")=="PASS": passing.append(data["cap_mib"])
print(min(passing) if passing else "none")
PY
}

lower_cap() {
  local selected=$1 previous=none
  for cap in "${caps[@]}"; do
    [[ "$cap" -ge "$selected" ]] && break
    previous=$cap
  done
  echo "$previous"
}

headline_matrix() {
  for id in H0 H1 H2; do
    read -r workload logn <<<"${WORKLOADS[$id]}"
    for mode in M0 M1 M2; do
      for rep in 1 2 3 4 5; do run_direct "$workload" "$mode" "$logn" "$rep" headline 0; done
      if [[ "$id" == H0 ]]; then run_cap "$workload" "$mode" "$logn" 256 1 cap 0; fi
    done
    for mode in M3 M4; do
      for cap in "${caps[@]}"; do run_cap "$workload" "$mode" "$logn" "$cap" 1 cap 0; done
      stable=$(minimum_cap "$workload" "$mode" cap)
      [[ "$stable" != none ]] || continue
      for rep in 1 2 3 4 5; do run_cap "$workload" "$mode" "$logn" "$stable" "$rep" headline 0; done
      lower=$(lower_cap "$stable")
      if [[ "$lower" != none ]]; then
        for rep in 1 2 3 4 5; do run_cap "$workload" "$mode" "$logn" "$lower" "$rep" boundary 0; done
      fi
    done
  done
}

identity_runs() {
  for id in H0 H1 H2; do
    read -r workload logn <<<"${WORKLOADS[$id]}"
    run_direct "$workload" M0 "$logn" 1 identity 1
    run_direct "$workload" M2 "$logn" 1 identity 1
    for mode in M3 M4; do
      stable=$(minimum_cap "$workload" "$mode" cap)
      [[ "$stable" != none ]] && run_cap "$workload" "$mode" "$logn" "$stable" 1 identity 1
    done
  done
}

scaling_runs() {
  for k in 1 4 10 25 52; do
    case "$k" in 1) logn=15;; 4) logn=16;; 10) logn=17;; 25|52) logn=18;; esac
    workload="S-WK-k${k}-r1-d32-sparse_merkle"
    for rep in 1 2 3 4 5; do run_cap "$workload" M4 "$logn" 256 "$rep" composition 0; done
  done
  for r in 0 1 2 4 8; do
    if [[ "$r" == 0 ]]; then workload="S-WK-k8-r0-d0-none"; logn=16; reps=5
    else workload="S-WK-k8-r${r}-d32-sparse_merkle"; case "$r" in 1) logn=16;; 2|4) logn=17;; 8) logn=18;; esac; [[ "$r" == 2 ]] && reps=3 || reps=5
    fi
    for rep in $(seq 1 "$reps"); do run_cap "$workload" M4 "$logn" 256 "$rep" revocation 0; done
  done
}

case "$phase" in
  headline) headline_matrix ;;
  identity) identity_runs ;;
  scaling) scaling_runs ;;
  all) headline_matrix; identity_runs; scaling_runs ;;
  *) echo "expected headline, identity, scaling, or all" >&2; exit 2 ;;
esac
