#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

(
  cd production_group
  cargo fmt --all -- --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo run --release
)
