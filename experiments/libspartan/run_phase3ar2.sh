#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p results

cargo generate-lockfile
cargo fmt --all -- --check
cargo clippy --bin phase3ar2 -- -D warnings
cargo test --release
cargo build --release --bin phase3ar2

runner="$PWD/target/release/phase3ar2"

"$runner" upstream
"$runner" native
"$runner" remote
"$runner" integration
"$runner" negative-tests
"$runner" finalize

python3 -m json.tool results/THINWALLET_LIBSPARTAN_UPSTREAM_BASELINE.json >/dev/null
python3 -m json.tool results/phase3ar2_summary.json >/dev/null
