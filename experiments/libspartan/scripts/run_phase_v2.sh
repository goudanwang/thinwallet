#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p results

cargo fmt --all -- --check
cargo test --release
cargo build --release --bin phase_v2_pbmo

runner="$PWD/target/release/phase_v2_pbmo"
for log_size in 12 14 16 18; do
  for mode in upstream native plain semi malicious; do
    "$runner" "$mode" "$log_size"
  done
done

scripts/run_phase_v2_memory_caps.sh
python3 scripts/collect_phase_v2_results.py
python3 -m json.tool results/phase_v2_summary.json >/dev/null
