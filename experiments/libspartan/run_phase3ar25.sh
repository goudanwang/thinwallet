#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
cargo fmt --all -- --check
cargo clippy --bin phase3ar25 -- -D warnings
cargo test --release
cargo build --release --bin phase3ar25
./target/release/phase3ar25
python3 -m json.tool physical_msm_inventory.json >/dev/null
python3 -m json.tool logical_commitment_inventory.json >/dev/null
