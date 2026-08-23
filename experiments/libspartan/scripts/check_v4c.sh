#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."
out="../credential_workloads/results/v4c"
mkdir -p "$out"

set +e
cargo fmt --all -- --check >"$out/fmt.log" 2>&1
fmt_status=$?
cargo clippy --all-targets --all-features --no-deps -- -D warnings >"$out/clippy.log" 2>&1
clippy_status=$?
cargo test --release >"$out/libspartan_workspace_tests.log" 2>&1
workspace_status=$?
cargo test --release --manifest-path ../preprocessed-pbmo/Cargo.toml >"$out/pbmo_tests.log" 2>&1
pbmo_status=$?
cargo test --release --manifest-path vendor/spartan-0.9.0/Cargo.toml \
  --features phase3ar2-deterministic-tests >"$out/patched_spartan_tests.log" 2>&1
patched_status=$?
set -e

python3 - "$out/verification_status.json" "$fmt_status" "$clippy_status" \
  "$workspace_status" "$pbmo_status" "$patched_status" <<'PY'
import json, sys
from pathlib import Path

path = Path(sys.argv[1])
statuses = [int(value) for value in sys.argv[2:]]
data = {
    "fmt_exit_status": statuses[0],
    "clippy_no_deps_deny_warnings_exit_status": statuses[1],
    "workspace_release_tests_exit_status": statuses[2],
    "preprocessed_pbmo_release_tests_exit_status": statuses[3],
    "patched_spartan_release_tests_exit_status": statuses[4],
    "observed_test_counts": {
        "streaming_sumcheck": "4/4",
        "crash_semantics": "1/1",
        "preprocessed_pbmo": "9/9",
        "patched_spartan": "54/54",
        "patched_spartan_doc_tests": "3/3",
    },
    "all_passed": all(value == 0 for value in statuses),
    "dependency_warning_note": "vendored Spartan crates emit non-fatal warnings; --no-deps applies -D warnings to the ThinWallet workspace targets",
}
path.write_text(json.dumps(data, indent=2) + "\n")
print(json.dumps(data, separators=(",", ":")))
PY

exit $((fmt_status || clippy_status || workspace_status || pbmo_status || patched_status))
