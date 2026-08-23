#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
for repetition in 12 13 14 15 16; do
  scripts/run_v3b_once.sh FS3 18 512 "$repetition"
done
