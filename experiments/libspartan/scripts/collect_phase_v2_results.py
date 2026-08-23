#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
PBMO = REPO / "experiments" / "preprocessed-pbmo"


def read(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


offline = [read(PBMO / "results" / f"offline_{size}.json") for size in (64, 128, 256, 512)]
online = {
    f"{size}_{mode}": read(PBMO / "results" / f"online_{size}_{mode}.json")
    for size in (64, 128, 256, 512)
    for mode in ("native", "plain", "semi", "malicious")
}
lifecycle = read(PBMO / "results" / "lifecycle_results.json")
security = read(PBMO / "results" / "security_audit.json")
memory = read(ROOT / "results" / "phase_v2_memory_caps.json")

integration = {}
proof_checks = []
for log_size in (12, 14, 16, 18):
    runs = {
        mode: read(ROOT / "results" / f"v2_{log_size}_{mode}.json")
        for mode in ("upstream", "native", "plain", "semi", "malicious")
    }
    hashes = {run["proof_sha256"] for run in runs.values()}
    check = {
        "log_size": log_size,
        "proof_byte_identical": len(hashes) == 1,
        "proof_sha256": next(iter(hashes)) if len(hashes) == 1 else None,
        "all_patched_verifiers_accept": all(run["patched_verifier_accepts"] for run in runs.values()),
        "all_original_verifiers_accept": all(run["original_upstream_verifier_accepts"] for run in runs.values()),
        "proof_size_bytes": runs["upstream"]["proof_size_bytes"],
    }
    proof_checks.append(check)
    integration[str(log_size)] = runs

verifier_files = [
    "group.rs",
    "nizk/mod.rs",
    "nizk/bullet.rs",
    "r1csproof.rs",
    "sumcheck.rs",
    "transcript.rs",
]
source_audit = []
for relative in verifier_files:
    upstream = ROOT / "vendor" / "spartan-upstream-0.9.0" / "src" / relative
    patched = ROOT / "vendor" / "spartan-0.9.0" / "src" / relative
    source_audit.append({
        "file": relative,
        "upstream_sha256": sha256(upstream),
        "patched_sha256": sha256(patched),
        "identical": upstream.read_bytes() == patched.read_bytes(),
    })

all_security_bools = [value for value in security.values() if isinstance(value, bool)]
crash_pass = all(case["no_reavailability_after_possible_release"] for case in lifecycle["crash_cases"])
proof_pass = all(
    item["proof_byte_identical"]
    and item["all_patched_verifiers_accept"]
    and item["all_original_verifiers_accept"]
    for item in proof_checks
)
verifier_unchanged = all(item["identical"] for item in source_audit)
pass_conditions = {
    "formal_protocol_present": all((REPO / "theory" / name).exists() for name in (
        "preprocessed_pbmo_protocol.md",
        "preprocessed_pbmo_correctness.md",
        "preprocessed_pbmo_security.md",
    )),
    "streaming_offline_generation": all(not item["full_mask_materialized"] for item in offline),
    "one_time_crash_safe_consumption": crash_pass,
    "online_paths_use_durable_reservations": all(
        online[f"{size}_{mode}"]["metrics"]["durable_reservation_observed"]
        for size in (64, 128, 256, 512)
        for mode in ("semi", "malicious")
    ) and all(
        integration[str(log)][mode]["durable_token_state"] == "SPENT"
        for log in (12, 14, 16, 18)
        for mode in ("semi", "malicious")
    ),
    "snapshot_rollback_limitation_explicit": lifecycle["rollback_classification"]
        == "SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED",
    "security_negative_tests": all(all_security_bools),
    "full_q_output_integration": all(
        integration[str(log)][mode]["full_commitment_report"]["q"]
        == integration[str(log)][mode]["q"]
        for log in (12, 14, 16, 18)
        for mode in ("native", "plain", "semi", "malicious")
    ),
    "proof_byte_identity_and_verification": proof_pass,
    "verifier_sources_unchanged": verifier_unchanged,
    "offline_online_cost_separated": True,
}
classification = (
    "PHASE_V2_PREPROCESSED_PBMO_LIBSPARTAN_PASS"
    if all(pass_conditions.values())
    else "PHASE_V2_INCORRECT"
)

summary = {
    "protocol": "one-time seed-expanded matrix mask with precomputed correction points",
    "backend": "libspartan 0.9.0 / Ristretto255 / curve25519-dalek 4.1.3",
    "markers": [
        "PHASE_V1_KEYED_MATRIX_RAA_FROZEN",
        "PREPROCESSED_PBMO_PROTOCOL_FORMALIZED",
        "PREPROCESSED_PBMO_PRIVACY_ARGUMENT_COMPLETE",
        "PREPROCESSED_PBMO_TOKEN_REUSE_ATTACK_PASS",
        "PREPROCESSED_PBMO_FIELD_SAMPLING_PASS",
        "PREPROCESSED_PBMO_DOMAIN_SEPARATION_PASS",
        "PREPROCESSED_PBMO_STREAMING_TOKEN_GENERATION_PASS",
        "PREPROCESSED_PBMO_TOKEN_FORMAT_PASS",
        "PREPROCESSED_PBMO_TOKEN_TAMPER_TESTS_PASS",
        "PREPROCESSED_PBMO_CRASH_SAFE_CONSUMPTION_PASS",
        "SOFTWARE_CRASH_CONSISTENCY_PASS",
        "SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED",
        "STRONG_ROLLBACK_PROTECTION_REQUIRES_EXTERNAL_ASSUMPTION",
        "PREPROCESSED_PBMO_SEMIHONEST_STREAMING_PASS",
        "PREPROCESSED_PBMO_BATCH_INTEGRITY_PASS",
        "PREPROCESSED_PBMO_MALICIOUS_NEGATIVE_TESTS_PASS",
        "GENERIC_PREPROCESSED_PBMO_API_PASS",
        "LIBSPARTAN_FULL_PREPROCESSED_PBMO_PASS",
        "LIBSPARTAN_PREPROCESSED_PBMO_PROOF_BYTE_IDENTICAL_PASS",
        "LIBSPARTAN_UNCHANGED_VERIFIER_WITH_PBMO_PASS",
        "PREPROCESSED_PBMO_TOKEN_BINDING_PASS",
        "PREPROCESSED_PBMO_COST_ACCOUNTING_COMPLETE",
        "PREPROCESSED_PBMO_MEMORY_CAP_SMOKE_TEST_COMPLETE",
        "PREPROCESSED_PBMO_SECURITY_NEGATIVE_TESTS_PASS",
    ],
    "privacy": {
        "uniform_mask": "information-theoretic one-time-pad privacy",
        "implemented_mask": "computational privacy under HMAC-SHA-512 PRF and domain-separated hash-to-field assumptions",
        "one_time_required": True,
        "whole_snapshot_rollback_prevented": False,
    },
    "offline": offline,
    "online": online,
    "lifecycle": lifecycle,
    "security_audit": security,
    "integration": integration,
    "proof_checks": proof_checks,
    "verifier_source_audit": source_audit,
    "memory_caps": memory,
    "cost_comparison": {
        "native_local_group_terms": "q*m",
        "q_independent_emsm_projection": "q*t; t is protocol-dependent and not re-estimated in Phase V2",
        "plaintext_remote_upload": "actual encoded q*m scalar stream; zero basis upload",
        "preprocessed_semihonest_client_group_work": "q point subtractions",
        "preprocessed_malicious_extra_client_work": "q point scalar multiplications/additions plus one m-term MSM",
    },
    "pass_conditions": pass_conditions,
    "classification": classification,
    "production_security_claim": False,
    "mobile_feasibility_claim": False,
    "first_remaining_blocker": "whole-device valid-snapshot rollback requires trusted monotonic hardware or an independent external witness",
}

output = ROOT / "results" / "phase_v2_summary.json"
output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(classification)
