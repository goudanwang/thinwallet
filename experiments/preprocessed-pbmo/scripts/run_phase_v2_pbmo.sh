#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p results/tokens

cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --release
cargo build --release --bin phase_v2_pbmo

runner="$PWD/target/release/phase_v2_pbmo"
for size in 64 128 256 512; do
  "$runner" offline "$size" "$size" "results/offline_${size}.json"
done
for size in 64 128 256 512; do
  for mode in native plain semi malicious; do
    "$runner" online "$mode" "$size" "$size" "results/online_${size}_${mode}.json"
  done
done
"$runner" lifecycle results/lifecycle_results.json
"$runner" audit results/security_audit.json

python3 -m json.tool results/security_audit.json >/dev/null
python3 -m json.tool results/lifecycle_results.json >/dev/null

