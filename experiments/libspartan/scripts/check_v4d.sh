#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.."
out="../credential_workloads/results/v4d"
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
./target/release/phase_v4c_profile_s "$out/profile_s_audit.json" \
  >"$out/profile_s_audit.stdout" 2>"$out/profile_s_audit.stderr"
profile_status=$?
./target/release/phase_v2_pbmo run-security-tests \
  >"$out/pbmo_security_smoke.json" 2>"$out/pbmo_security_smoke.stderr"
pbmo_security_status=$?
set -e

python3 - "$out/verification_status.json" \
  "$fmt_status" "$clippy_status" "$workspace_status" "$pbmo_status" \
  "$patched_status" "$profile_status" "$pbmo_security_status" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
statuses = [int(value) for value in sys.argv[2:]]
names = [
    "fmt_exit_status",
    "clippy_no_deps_deny_warnings_exit_status",
    "workspace_release_tests_exit_status",
    "preprocessed_pbmo_release_tests_exit_status",
    "patched_spartan_release_tests_exit_status",
    "profile_s_audit_exit_status",
    "pbmo_security_smoke_exit_status",
]
payload = dict(zip(names, statuses))
payload["all_executed_checks_passed"] = all(status == 0 for status in statuses)
payload["v4d_specific_unimplemented_security_tests"] = [
    "compact credential-witness source tampering and index swap",
    "MiMC replay-version mismatch on an authenticated compact source",
    "multi-credential revocation path assignment swap",
    "external sparse-R1CS construction crash recovery",
]
payload["software_only_snapshot_rollback_not_prevented"] = True
path.write_text(json.dumps(payload, indent=2) + "\n")
print(json.dumps(payload, separators=(",", ":")))
PY

exit $((fmt_status || clippy_status || workspace_status || pbmo_status || patched_status || profile_status || pbmo_security_status))
