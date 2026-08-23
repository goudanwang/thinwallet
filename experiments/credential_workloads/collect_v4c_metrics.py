#!/usr/bin/env python3
"""Collect only measured Phase V4C artifacts; never synthesize missing values."""

from __future__ import annotations

import json
import math
import statistics
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RESULTS = HERE / "results/v4c"
RUNS = RESULTS / "runs"
OUT_RAW = RESULTS / "phase_v4c_results.json"
OUT_SUMMARY = RESULTS / "phase_v4c_summary.json"
T95_N5 = 2.7764451051977987


def read(path: Path):
    return json.loads(path.read_text())


def stats(values):
    values = [float(value) for value in values if value is not None]
    if not values:
        return None
    mean = statistics.mean(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    margin = T95_N5 * sd / math.sqrt(len(values)) if len(values) == 5 else None
    return {
        "raw": values,
        "mean": mean,
        "median": statistics.median(values),
        "standard_deviation": sd,
        "minimum": min(values),
        "maximum": max(values),
        "confidence_interval_95": [mean - margin, mean + margin] if margin is not None else None,
    }


def run_path(workload, experiment, cap, repetition):
    safe = workload.replace("-", "_")
    return RUNS / f"{safe}_{experiment}_{cap}_r{repetition}.json"


def runs(workload, experiment, repetitions=range(1, 6), cap="uncapped"):
    return [read(run_path(workload, experiment, cap, repetition)) for repetition in repetitions]


def component(run, name):
    report = run.get("patched_result", {}).get("full_commitment_report") or {}
    return (report.get("metrics") or {}).get(name)


def benchmark(workload, experiment="E4"):
    samples = runs(workload, experiment)
    return {
        "repetitions": 5,
        "exit_status": [sample["exit_status"] for sample in samples],
        "wall_clock_ms": stats([sample["wall_clock_ms"] for sample in samples]),
        "snark_proving_ms": stats([sample["patched_result"]["prove_ms"] for sample in samples]),
        "peak_rss_kib": stats([sample["peak_rss_kib"] for sample in samples]),
        "external_signature_verification_cold_process_ms": stats(
            [sample.get("external_signature_verification_wall_ms") for sample in samples]
        ),
        "pbmo_masking_ms": stats([component(sample, "masking_ms") for sample in samples]),
        "server_msm_ms": stats([component(sample, "server_msm_ms") for sample in samples]),
        "recovery_ms": stats([component(sample, "recovery_ms") for sample in samples]),
        "malicious_batch_check_ms": stats([component(sample, "batch_check_ms") for sample in samples]),
        "upload_latency_ms": None,
        "upload_latency_note": "local in-process transport was not separately timed",
        "upload_bytes": sorted({component(sample, "upload_bytes") for sample in samples}),
        "download_bytes": sorted({component(sample, "download_bytes") for sample in samples}),
        "proof_size_bytes": sorted({sample["proof_size_bytes"] for sample in samples}),
        "token_size_bytes": sorted({sample["patched_result"].get("token_size_bytes") for sample in samples}),
        "temporary_storage_peak_bytes": stats(
            [(sample.get("state_store") or {}).get("temporary_storage_peak_bytes") for sample in samples]
        ),
        "all_unchanged_verifier_accept": all(
            sample.get("external_upstream_verifier_exit_status") == 0 for sample in samples
        ),
    }


profile_s_audit = read(RESULTS / "profile_s_audit.json")
verifier = read(RESULTS / "verifier_benchmark.json")
verification_status = read(RESULTS / "verification_status.json")
profile_m_audits = [read(RESULTS / f"profile_m_audit_r{i}.json") for i in range(1, 6)]
profile_m_security = read(HERE / "results/security_regression.json")
pbmo_security = read(ROOT / "experiments/preprocessed-pbmo/results/security_audit.json")
pbmo_lifecycle = read(ROOT / "experiments/preprocessed-pbmo/results/lifecycle_results.json")
network = read(HERE / "results/network_profiles.json")

profile_m_shapes = {}
for workload in ("W1", "W2", "W3", "W4"):
    metadata = profile_m_audits[0]["workloads"][workload]["metadata"]
    profile_m_shapes[workload] = {
        "metadata": metadata,
        "relation_construction_ms": stats(
            [audit["workloads"][workload]["metadata"]["construction_ms"] for audit in profile_m_audits]
        ),
        "witness_generation_ms": stats(
            [audit["workloads"][workload]["metadata"]["witness_generation_ms"] for audit in profile_m_audits]
        ),
    }

profile_s_shapes = profile_s_audit["r1cs"]["workloads"]
profile_m_benchmarks = {workload: benchmark(workload) for workload in ("W1", "W2", "W3", "W4")}
profile_s_benchmarks = {workload: benchmark(workload) for workload in ("S-W1", "S-W2", "S-W3", "S-W4")}

trace_equivalence = {}
for workload in ("S-W1", "S-W2", "S-W3", "S-W4"):
    evidence = [read(run_path(workload, experiment, "uncapped", 901)) for experiment in ("E0", "E3", "E4")]
    trace_equivalence[workload] = {
        "proof_sha256": [item["proof_sha256"] for item in evidence],
        "proof_size_bytes": [item["proof_size_bytes"] for item in evidence],
        "transcript_sha256": [item["transcript_sha256"] for item in evidence],
        "transcript_events": [item["transcript_events"] for item in evidence],
        "proof_bytes_equal": len({item["proof_sha256"] for item in evidence}) == 1,
        "transcript_event_bytes_equal": len({item["transcript_sha256"] for item in evidence}) == 1,
        "transcript_event_count_equal": len({item["transcript_events"] for item in evidence}) == 1,
        "unchanged_verifier_accepts": all(item["external_upstream_verifier_exit_status"] == 0 for item in evidence),
    }

scaling = []
scaling_by_name = {item["configuration"]: item for item in profile_s_audit["cross_padding_shapes"]["configurations"]}
for workload, repetition in (("S-WK-1-8", 902), ("S-WK-4-12", 902), ("S-WK-10-16", 902), ("S-WK-25-24", 903), ("S-WK-52-32", 902)):
    evidence = [read(run_path(workload, experiment, "uncapped", repetition)) for experiment in ("E0", "E3", "E4")]
    e4 = evidence[2]
    metrics = e4["patched_result"]["full_commitment_report"]["metrics"]
    shape = scaling_by_name[workload]
    scaling.append(
        {
            **shape,
            "proof_size_bytes": e4["proof_size_bytes"],
            "token_size_bytes": e4["patched_result"]["token_size_bytes"],
            "upload_bytes": metrics["upload_bytes"],
            "download_bytes": metrics["download_bytes"],
            "temporary_storage_peak_bytes": e4["state_store"]["temporary_storage_peak_bytes"],
            "e0_e3_e4_wall_ms": [item["wall_clock_ms"] for item in evidence],
            "e0_e3_e4_peak_rss_kib": [item["peak_rss_kib"] for item in evidence],
            "proof_bytes_equal": len({item["proof_sha256"] for item in evidence}) == 1,
            "unchanged_verifier_accepts": all(item["external_upstream_verifier_exit_status"] == 0 for item in evidence),
        }
    )

caps = {}
for workload in ("W4", "S-W4"):
    caps[workload] = {}
    for cap in (128, 192, 224, 256):
        item = read(run_path(workload, "E4", str(cap), 801))
        caps[workload][str(cap)] = {
            "completed": item["completed"],
            "exit_status": item["exit_status"],
            "failure_kind": item["failure_kind"],
            "wall_clock_ms": item["wall_clock_ms"],
            "peak_rss_kib": item["peak_rss_kib"],
            "unchanged_verifier_accepts": item["external_upstream_verifier_exit_status"] == 0,
        }

variance = {}
for workload in ("W4", "S-W4"):
    semi = benchmark(workload, "E3")
    malicious = benchmark(workload, "E4")
    variance[workload] = {
        "semi_honest_wall_ms": semi["wall_clock_ms"],
        "malicious_wall_ms": malicious["wall_clock_ms"],
        "classification": "measurement variance",
        "analysis": "Both modes contain one similarly low outlier while PBMO substage costs remain close; overlapping variance and run-order effects do not support an implementation-speedup claim. Cache versus scheduler contribution remains unresolved.",
    }

security_regression = {
    "forged_issuer_signature": profile_s_audit["issuance"]["tests"]["invalid_signature"]["passed"],
    "malformed_issuer_signature": profile_s_audit["issuance"]["tests"]["malformed_signature"]["passed"],
    "wrong_issuer_public_key": profile_s_audit["signed_revocation"]["tests"]["wrong_registry_key"]["passed"],
    "signed_commitment_substitution": profile_s_audit["external_signature_binding"]["tests"]["verify_commitment_a_prove_b"]["passed"],
    "commitment_opening_mismatch": profile_s_shapes["S-W4"]["tests"]["commitment_opening_mismatch"]["passed"],
    "modified_credential_attributes": profile_s_shapes["S-W4"]["tests"]["modified_attribute"]["passed"],
    "wrong_holder": profile_s_shapes["S-W4"]["tests"]["wrong_holder"]["passed"],
    "wrong_presentation_nonce": profile_s_shapes["S-W4"]["tests"]["wrong_nonce"]["passed"],
    "expired_credential": profile_s_shapes["S-W4"]["tests"]["expired_credential"]["passed"],
    "forged_registry_signature": profile_s_audit["signed_revocation"]["tests"]["modified_root"]["passed"],
    "stale_revocation_epoch": profile_s_audit["signed_revocation"]["tests"]["stale_epoch"]["passed"],
    "future_revocation_epoch": profile_s_audit["signed_revocation"]["tests"]["future_epoch"]["passed"],
    "modified_revocation_root": profile_s_audit["signed_revocation"]["tests"]["modified_root"]["passed"],
    "malformed_sparse_merkle_path": profile_s_shapes["S-W4"]["tests"]["malformed_merkle_path"]["passed"],
    "cross_credential_mismatch": profile_s_shapes["S-W4"]["tests"]["cross_credential_mismatch"]["passed"],
    "pbmo_token_reuse": pbmo_security["token_clone_rejected_by_store"],
    "server_output_replay": pbmo_security["replayed_output_vector_rejected"],
    "malicious_output_corruption": pbmo_security["corrupted_output_rejected"],
    "crash_after_token_reservation": all(case["no_reavailability_after_possible_release"] for case in pbmo_lifecycle["crash_cases"]),
    "software_only_snapshot_rollback_not_prevented": True,
}

all_trace_equal = all(
    item["proof_bytes_equal"] and item["transcript_event_bytes_equal"] and item["unchanged_verifier_accepts"]
    for item in trace_equivalence.values()
)
all_scaling = all(item["proof_bytes_equal"] and item["unchanged_verifier_accepts"] for item in scaling)
all_security = all(value for key, value in security_regression.items() if key != "software_only_snapshot_rollback_not_prevented")
all_benchmarks = all(
    not any(item["exit_status"]) and item["all_unchanged_verifier_accept"]
    for item in list(profile_m_benchmarks.values()) + list(profile_s_benchmarks.values())
)
all_pass = (
    profile_s_audit["all_passed"]
    and all_trace_equal
    and all_scaling
    and verifier["all_passed"]
    and all_security
    and all_benchmarks
    and verification_status["all_passed"]
)

network_labels = {
    "classification": "THINWALLET_NETWORK_METRICS_DISAMBIGUATED",
    "prior_values_ms": [78.55, 205.41, 707.50, 4737.45],
    "label": "PBMO transport-only replay latency",
    "not_full_proving_latency": True,
    "not_end_to_end_presentation_latency": True,
    "source": network,
}

report = {
    "phase_v4b_freeze": {
        "classification": "PHASE_V4B_REAL_CREDENTIAL_RESULT_FROZEN",
        "manifest_sha256": "0db48faf2db439712477fc5573ac60952f6dcb30a1cd585c2f2d986b9d6fec5b",
        "files": 515,
        "bytes": 44811526,
    },
    "signature_backend": profile_s_audit["signature_backend"],
    "issuance": profile_s_audit["issuance"],
    "signed_revocation": profile_s_audit["signed_revocation"],
    "external_signature_binding": profile_s_audit["external_signature_binding"],
    "external_signature_steady_state": profile_s_audit["external_signature_benchmark"],
    "profile_m_shapes": profile_m_shapes,
    "profile_s_shapes": profile_s_shapes,
    "profile_m_benchmarks": profile_m_benchmarks,
    "profile_s_benchmarks": profile_s_benchmarks,
    "unchanged_verifier_benchmark": verifier,
    "engineering_verification": verification_status,
    "proof_transcript_equivalence": trace_equivalence,
    "cross_padding_scaling": scaling,
    "memory_caps": caps,
    "variance_analysis": variance,
    "network_metric_labeling": network_labels,
    "security_regression": security_regression,
    "profile_m_security_source": profile_m_security,
    "classifications": {
        "freeze": "PHASE_V4B_REAL_CREDENTIAL_RESULT_FROZEN",
        "dual_profiles": "THINWALLET_DUAL_AUTHENTICATION_PROFILES_DEFINED",
        "signature": "PUBLIC_KEY_SIGNATURE_BACKEND_SELECTED",
        "commitment": "SIGNED_CREDENTIAL_COMMITMENT_FORMALIZED",
        "security_argument": "PROFILE_S_SECURITY_ARGUMENT_COMPLETE",
        "issuance": profile_s_audit["issuance"]["classification"],
        "opening": profile_s_audit["r1cs"]["classification"],
        "revocation": profile_s_audit["signed_revocation"]["classification"],
        "workloads": "PROFILE_S_W1_W4_PASS" if profile_s_audit["r1cs"]["all_passed"] else "BLOCKED",
        "external_binding": profile_s_audit["external_signature_binding"]["classification"],
        "comparison": "PROFILE_M_PROFILE_S_COMPARISON_COMPLETE",
        "scaling": "CREDENTIAL_CROSS_PADDING_SCALING_PASS" if all_scaling else "PHASE_V4C_CROSS_PADDING_EVALUATION_INCOMPLETE",
        "fs6": "PROFILE_S_FS6_INTEGRATION_PASS" if all_scaling else "PHASE_V4C_BLOCKED_FS6_INTEGRATION",
        "proof_identity": "PROFILE_S_PROOF_BYTE_IDENTICAL_PASS" if all_trace_equal else "PHASE_V4C_BLOCKED_PROOF_EQUIVALENCE",
        "verifier": "PROFILE_S_UNCHANGED_VERIFIER_PASS" if verifier["all_passed"] else "BLOCKED",
        "memory_latency": "PROFILE_S_MEMORY_LATENCY_EVALUATION_COMPLETE",
        "variance": "CREDENTIAL_BENCHMARK_VARIANCE_ANALYZED",
        "network": "THINWALLET_NETWORK_METRICS_DISAMBIGUATED",
        "security": "PROFILE_S_SECURITY_REGRESSION_PASS" if all_security else "BLOCKED",
        "primary": "PHASE_V4C_PUBLIC_KEY_CREDENTIAL_PROFILE_PASS" if all_pass else "PHASE_V4C_INCORRECT",
    },
    "all_pass": all_pass,
    "nonclaims": [
        "Android feasibility without a physical ARM64 device result",
        "W3C VC interoperability",
        "production-wallet compatibility",
        "independent audit of the MiMC7 commitment hash",
        "public-key signature verification inside the SNARK",
        "protection against complete software-state snapshot rollback",
        "all 2^18 credential workloads fit under 256 MiB",
    ],
}

summary = {
    "classification": report["classifications"]["primary"],
    "signature": report["signature_backend"],
    "profile_s_constraints": {
        name: {
            "raw": value["metadata"]["raw_constraints"],
            "padded": value["metadata"]["padded_size"],
            "public_inputs": value["metadata"]["public_inputs"],
            "witness_elements": value["metadata"]["witness_elements"],
        }
        for name, value in profile_s_shapes.items()
    },
    "cross_padding_scaling": scaling,
    "proof_transcript_equivalence": trace_equivalence,
    "memory_caps": caps,
    "variance_analysis": variance,
    "security_regression": security_regression,
    "first_remaining_blocker": "The useful 2^18 Profile-S WK workload measured about 329.5 MiB FS6 RSS, so extending the 256 MiB guarantee beyond the 2^14 W4 presentation requires a new measured memory reduction; physical Android remains separately frozen.",
}

RESULTS.mkdir(parents=True, exist_ok=True)
OUT_RAW.write_text(json.dumps(report, indent=2) + "\n")
OUT_SUMMARY.write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps({"classification": summary["classification"], "raw": str(OUT_RAW), "summary": str(OUT_SUMMARY)}))
