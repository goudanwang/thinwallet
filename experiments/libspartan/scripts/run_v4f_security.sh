#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."
result_root="${THINWALLET_SECURITY_RESULTS_ROOT:-$PWD/../../results/v4f}"
out="$result_root/security"
mkdir -p "$out"

set +e
cargo fmt --all -- --check >"$out/fmt.log" 2>&1; fmt=$?
cargo clippy --all-targets --all-features --no-deps -- -D warnings >"$out/clippy.log" 2>&1; clippy=$?
cargo test --release >"$out/libspartan-tests.log" 2>&1; libtests=$?
cargo test --release --manifest-path ../preprocessed-pbmo/Cargo.toml >"$out/pbmo-tests.log" 2>&1; pbmotests=$?
cargo test --release --manifest-path vendor/spartan-0.9.0/Cargo.toml --features phase3ar2-deterministic-tests >"$out/patched-spartan-tests.log" 2>&1; patchedtests=$?
./target/release/phase_v4e_credential_source >"$out/source-audit.stdout" 2>"$out/source-audit.stderr"; source=$?
./target/release/phase_v4c_profile_s "$out/profile-s-audit.json" >"$out/profile-s.stdout" 2>"$out/profile-s.stderr"; profile=$?
./target/release/phase_v2_pbmo run-security-tests >"$out/pbmo-security.json" 2>"$out/pbmo-security.stderr"; pbmosec=$?
set -e

python3 - "$result_root/security_regression.json" "$out" "$fmt" "$clippy" "$libtests" "$pbmotests" "$patchedtests" "$source" "$profile" "$pbmosec" <<'PY'
import json, sys
from pathlib import Path
destination, out = Path(sys.argv[1]), Path(sys.argv[2])
names=["fmt","clippy","libspartan_release_tests","preprocessed_pbmo_release_tests","patched_spartan_release_tests","authenticated_source_audit","profile_s_audit","pbmo_security_smoke"]
statuses=dict(zip(names,map(int,sys.argv[3:])))
tests=[{"name":name,"passed":status==0,"evidence":str(out / (name+".log"))} for name,status in statuses.items()]
source=json.loads(Path("../credential_workloads/results/v4e/phase_v4e_semantic_audit.json").read_text())
for test in source["security_tests"]:
    tests.append({"name":"authenticated_source/"+test["name"],"passed":test["passed"],"evidence":"experiments/credential_workloads/results/v4e/phase_v4e_semantic_audit.json"})
profile=json.loads((out/"profile-s-audit.json").read_text())
def walk(value,path="profile_s"):
    if isinstance(value,dict):
        if isinstance(value.get("passed"),bool):
            tests.append({"name":path,"passed":value["passed"],"evidence":str(out/"profile-s-audit.json")})
        for key,child in value.items(): walk(child,path+"/"+key)
    elif isinstance(value,list):
        for index,child in enumerate(value): walk(child,path+f"/{index}")
walk(profile)
pbmo=json.loads((out/"pbmo-security.json").read_text())
for key,value in pbmo.items():
    if isinstance(value,bool) and key != "full_android_regression_requires_physical_device":
        tests.append({"name":"pbmo/"+key,"passed":value,"evidence":str(out/"pbmo-security.json")})
for name in [
 "pbmo/token_reuse_and_response_replay", "pbmo/malicious_output_corruption",
 "pbmo/crash_before_reservation", "pbmo/crash_after_reservation",
 "pbmo/cleanup_after_aborted_proving"
]:
    tests.append({"name":name,"passed":statuses["preprocessed_pbmo_release_tests"]==0 and statuses["patched_spartan_release_tests"]==0,"evidence":"release test logs; provider/token/multi_state_store named tests"})
payload={
 "classification":"FINAL_DESKTOP_SECURITY_REGRESSION_PASS" if all(t["passed"] for t in tests) else "FINAL_DESKTOP_SECURITY_REGRESSION_FAIL",
 "all_passed":all(t["passed"] for t in tests), "authenticated_source_passed":sum(t["passed"] for t in source["security_tests"]),
 "authenticated_source_total":len(source["security_tests"]), "statuses":statuses, "tests":tests,
 "software_only_snapshot_rollback_not_prevented":True,
 "notes":["No physical Android test was run.","Full software snapshot rollback remains outside the guarantee."]
}
destination.write_text(json.dumps(payload,indent=2)+"\n")
print(json.dumps({"classification":payload["classification"],"tests":len(tests),"source":f'{payload["authenticated_source_passed"]}/{payload["authenticated_source_total"]}'}))
PY

exit $((fmt || clippy || libtests || pbmotests || patchedtests || source || profile || pbmosec))
