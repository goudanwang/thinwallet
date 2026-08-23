#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."

workloads=(S-W1 S-W4 S-WK-1-8 S-WK-4-12 S-WK-10-16 S-WK-25-24)
logs=(13 14 14 15 16 17)

for index in "${!workloads[@]}"; do
  repetition=$((701 + index))
  echo "V4D_SCALING_START:${workloads[$index]}"
  "$PWD/scripts/run_v4d_once.sh" \
    "${workloads[$index]}" E4 "${logs[$index]}" uncapped "$repetition"
  echo "V4D_SCALING_END:${workloads[$index]}"
done
