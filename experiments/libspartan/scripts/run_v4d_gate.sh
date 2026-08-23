#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

cap_mib="${1:-248}"
first_repetition="${2:-1}"
last_repetition="${3:-5}"

for repetition in $(seq "$first_repetition" "$last_repetition"); do
  echo "V4D_FORMAL_START:$repetition"
  "$PWD/scripts/run_v4d_cgroup_once.sh" S-WK-52-32 18 "$cap_mib" "$repetition"
  echo "V4D_FORMAL_END:$repetition"
done
