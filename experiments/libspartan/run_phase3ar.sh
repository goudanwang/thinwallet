#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$SCRIPT_DIR"

mkdir -p results

python3 - <<'PY'
import json
from pathlib import Path

p = Path("../real-backend-migration/results/phase3a_summary.json")
if p.exists():
    data = json.loads(p.read_text())
    data["backend_audit"]["classification"] = "PHASE3A_NO_SUITABLE_BACKEND_UNDER_FIXED_BN254_CONSTRAINT"
    data["backend_audit"]["selection_output"] = "NO_SUITABLE_REAL_SUMCHECK_BACKEND_UNDER_FIXED_BN254_CONSTRAINT"
    p.write_text(json.dumps(data, indent=2) + "\n")

c = Path("../real-backend-migration/candidates.json")
if c.exists():
    data = json.loads(c.read_text())
    data["selection_output"] = "NO_SUITABLE_REAL_SUMCHECK_BACKEND_UNDER_FIXED_BN254_CONSTRAINT"
    data["classification"] = "PHASE3A_NO_SUITABLE_BACKEND_UNDER_FIXED_BN254_CONSTRAINT"
    data["correction"] = "BACKEND_SELECTION_CONSTRAINT_CORRECTED"
    c.write_text(json.dumps(data, indent=2) + "\n")
PY

echo "BACKEND_SELECTION_CONSTRAINT_CORRECTED"

cargo generate-lockfile
cargo metadata --format-version 1 > results/cargo_metadata.json
cargo tree > results/cargo_tree.txt
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --release

PHASE3AR_LOG_SIZES="${PHASE3AR_LOG_SIZES:-12,14}" cargo run --release

python3 -m json.tool results/native_baseline.json >/dev/null
python3 -m json.tool results/ristretto_emsm.json >/dev/null
python3 -m json.tool results/phase3ar_summary.json >/dev/null
python3 -m json.tool operator_graph.json >/dev/null
python3 -m json.tool msm_inventory.json >/dev/null

cat results/phase3ar_summary.json
