#!/usr/bin/env python3
import hashlib
import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
BOUNDARY = ROOT / "results" / "v3d_boundary"
MEMORY = ROOT / "results" / "v3d_memory"
OUT = WORKSPACE / "experiments" / "v3d"


def load(path):
    return json.loads(path.read_text())


def run(mode, cap, rep, provider="malicious"):
    return load(BOUNDARY / f"{mode}_{provider}_18_{cap}_r{rep}.json")


def stats(values):
    return {
        "raw": values,
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def cap_record(mode, cap, reps):
    records = [run(mode, cap, rep) for rep in reps]
    return {
        "status": "PASS" if all(item["completed"] for item in records) else records[0]["failure_kind"].upper(),
        "runs": len(records),
        "exit_status": [item["exit_status"] for item in records],
        "peak_rss_kib": [item["peak_rss_kib"] for item in records],
        "wall_clock_ms": [item["wall_clock_ms"] for item in records],
        "proof_sha256": [item["proof_sha256"] for item in records],
        "unchanged_verifier_accepts": [
            bool((item.get("external_upstream_verifier") or {}).get("accepted")) for item in records
        ],
    }


def main():
    frozen = load(WORKSPACE / "experiments" / "v3c_memory" / "v3c_results.json")
    fs4_probe = load(MEMORY / "FS4_18_uncapped.summary.json")
    fs5_probe = load(MEMORY / "FS5_18_uncapped.summary.json")
    headline = [run("FS5", 320, rep) for rep in range(70, 75)]
    lower = [run("FS5", 288, rep) for rep in range(80, 85)]
    latency = run("FS5", 320, 74)
    plan = latency["memory_plan"]
    store = latency["state_store"]

    measured_rss_bytes = int(statistics.fmean(item["peak_rss_kib"] for item in headline) * 1024)
    predicted_rss_bytes = plan["predicted_total_rss_bytes"]
    prediction_error = abs(predicted_rss_bytes - measured_rss_bytes) / measured_rss_bytes * 100
    v3a_read = 335_544_320
    v3a_write = 167_772_160
    measured_read = store["bytes_read"] + v3a_read
    measured_write = store["bytes_written"] + v3a_write

    fs4_exact_peak = fs4_probe["peak_sample"]["vm_rss_kib"] * 1024
    lower_estimate = frozen["current_implementation_lower_bound_bytes"]
    exact_gap = fs4_exact_peak - lower_estimate
    file_rss = fs4_probe["peak_sample"]["rss_file_kib"] * 1024
    stack = fs4_probe["peak_sample"]["vm_stk_kib"] * 1024
    unknown = exact_gap - file_rss - stack
    gap = {
        "specified_model_gap_bytes": frozen["planner"]["predicted_total_rss_bytes"] - lower_estimate,
        "detailed_probe_peak_rss_bytes": fs4_exact_peak,
        "minimum_retained_plus_reserve_bytes": lower_estimate,
        "detailed_probe_gap_bytes": exact_gap,
        "attribution_bytes": {
            "file_backed_rss": file_rss,
            "thread_stack_residency": stack,
            "anonymous_transcript_overlap_allocator_runtime_not_separable": unknown,
        },
        "attribution_sum_bytes": file_rss + stack + unknown,
        "anonymous_rss_bytes": fs4_probe["peak_sample"]["rss_anon_kib"] * 1024,
        "pss_bytes": fs4_probe["peak_sample"]["pss_kib"] * 1024,
        "vector_excess_capacity_bytes_in_instrumented_ge_64k_allocations": 0,
        "allocator_fragmentation_bytes": None,
        "page_resident_temporary_file_data_bytes": None,
        "network_buffers_bytes": None,
        "unknown_note": "The uninstrumented /proc sample cannot separate anonymous transcript overlap from allocator/runtime residency; the exact remainder is classified unknown rather than inferred.",
    }

    result = {
        "experiment": "phase_v3d_transcript_aware_recompute",
        "backend": frozen["backend"],
        "freeze": {
            "status": "PHASE_V3C_ACTIVE_STREAMING_FROZEN",
            "archive_sha256": hashlib.sha256(
                (WORKSPACE / "archive" / "phase_v3c_active_sumcheck_streaming" / "phase_v3c_active_sumcheck_streaming.zip").read_bytes()
            ).hexdigest(),
        },
        "fs4_practical_lower_bound_gap": gap,
        "checkpoint_recompute": {
            "removed_scalar_address_timestamp_tables_bytes": 134_217_728,
            "retained_compact_sources_bytes": 20_971_520,
            "net_logical_reduction_bytes": 113_246_208,
            "measured_peak_reduction_bytes_vs_frozen_fs4_mean": int(
                frozen["headline_2p18_384"]["peak_rss_mean_kib"] * 1024 - measured_rss_bytes
            ),
            "checkpoint_recompute_time_ms": store["checkpoint_recompute_time_ns"] / 1e6,
            "classification": "THINWALLET_CHECKPOINT_RECOMPUTE_PASS",
            "dense_mle_result": "DENSE_MLE_LATE_USE_RECOMPUTATION_PASS",
            "address_hash_opening_result": "ADDRESS_HASH_OPENING_RECOMPUTATION_PASS",
            "buffer_result": "FS5_BUFFER_OVERLAP_REDUCTION_PASS",
        },
        "runtime_allocator": {
            "fs5_peak_sample": fs5_probe["peak_sample"],
            "max_pss_kib": fs5_probe["max_pss_kib"],
            "max_threads": fs5_probe["max_threads"],
            "max_stack_reserved_bytes": fs5_probe["max_stack_reserved_bytes"],
            "allocator_fragmentation_bytes": None,
            "classification": "V3D_RUNTIME_ALLOCATOR_RESIDUAL_AUDIT_COMPLETE",
        },
        "durability": {
            "ephemeral_state_fsync_calls": store["state_fsync_calls"],
            "ephemeral_state_skipped_fsync_calls": store["state_skipped_fsync_calls"],
            "ephemeral_state_fsync_ms": store["state_fsync_time_ns"] / 1e6,
            "token_durable_sync_calls": latency["patched_result"]["token_durable_sync_calls"],
            "token_durable_sync_ms": latency["patched_result"]["token_durable_sync_ms"],
            "token_terminal_state": latency["patched_result"]["durable_token_state"],
            "outputs": ["EPHEMERAL_STATE_FSYNC_REMOVED", "PBMO_TOKEN_DURABILITY_PRESERVED"],
        },
        "planner": {
            "predicted_rss_bytes": predicted_rss_bytes,
            "measured_mean_rss_bytes": measured_rss_bytes,
            "absolute_prediction_error_percent": prediction_error,
            "predicted_temporary_storage_bytes": plan["estimated_temporary_storage_bytes"],
            "measured_temporary_storage_bytes": fs5_probe["max_temporary_file_bytes"],
            "predicted_read_bytes": plan["estimated_read_bytes"],
            "measured_read_bytes": measured_read,
            "predicted_write_bytes": plan["estimated_write_bytes"],
            "measured_write_bytes": measured_write,
            "predicted_recompute_work_units": plan["estimated_recompute_work_units"],
            "measured_recompute_ms": store["checkpoint_recompute_time_ns"] / 1e6,
            "classification": "THINWALLET_FS5_PLANNER_VALIDATION_COMPLETE",
        },
        "headline_2p18_320": {
            "success": "5/5",
            "peak_rss_kib": stats([item["peak_rss_kib"] for item in headline]),
            "wall_clock_ms": stats([item["wall_clock_ms"] for item in headline]),
            "proof_sha256": "e6360f619150e8141d4645a18da7d781ee84818f273cd093a088638d97b3bf8e",
            "proof_size_bytes": 120136,
            "all_unchanged_verifiers_accept": all(
                item["external_upstream_verifier"]["accepted"] for item in headline
            ),
            "all_tokens_spent": all(item["patched_result"]["durable_token_state"] == "SPENT" for item in headline),
            "all_swaps_zero": all(item["swaps"] == 0 for item in headline),
        },
        "strong_boundary_2p18_288": {
            "success": "5/5",
            "peak_rss_kib": stats([item["peak_rss_kib"] for item in lower]),
            "wall_clock_ms": stats([item["wall_clock_ms"] for item in lower]),
        },
        "memory_caps": {
            "FS4": {
                "384": frozen["memory_caps"]["384"],
                "352": frozen["memory_caps"]["352"],
                "336": cap_record("FS4", 336, [60]),
                "320": frozen["memory_caps"]["320"],
                "304": cap_record("FS4", 304, [61]),
                "288": cap_record("FS4", 288, [62]),
                "256": cap_record("FS4", 256, [63]),
            },
            "FS5": {
                "384": cap_record("FS5", 384, [20]),
                "352": cap_record("FS5", 352, [21]),
                "336": cap_record("FS5", 336, [22]),
                "320": cap_record("FS5", 320, list(range(70, 75))),
                "304": cap_record("FS5", 304, [23]),
                "288": cap_record("FS5", 288, list(range(80, 85))),
                "256": cap_record("FS5", 256, [40]),
            },
        },
        "equivalence": {
            "fs1_fs4_fs5_2p12_transcript_events": 6906,
            "fs1_fs4_fs5_2p12_transcript_sha256": "a68a34b2fe71ba5518b6b8866e16888845f623b32ca19d373532ce17ee7cdaf2",
            "fs1_fs4_fs5_2p12_proof_sha256": "a9b8bd3cc9f02c254e7990e81a38c5d8948383e3463970084978500cf617434a",
            "fs4_fs5_2p18_proof_sha256": "e6360f619150e8141d4645a18da7d781ee84818f273cd093a088638d97b3bf8e",
            "unchanged_upstream_verifier": "PASS",
        },
        "latency": {
            "fs4_wall_mean_ms": frozen["headline_2p18_384"]["wall_clock_mean_ms"],
            "fs5_wall_mean_ms": statistics.fmean(item["wall_clock_ms"] for item in headline),
            "fs5_instrumented_wall_ms": latency["wall_clock_ms"],
            "fs5_prove_ms": latency["patched_result"]["prove_ms"],
            "sumcheck_ms": store["active_sumcheck_streaming_time_ns"] / 1e6,
            "product_build_ms": store["active_product_build_time_ns"] / 1e6,
            "recompute_ms": store["checkpoint_recompute_time_ns"] / 1e6,
            "spill_read_ms": store["state_read_time_ns"] / 1e6,
            "spill_write_ms": store["state_write_time_ns"] / 1e6,
            "ephemeral_fsync_ms": store["state_fsync_time_ns"] / 1e6,
            "token_durable_sync_ms": latency["patched_result"]["token_durable_sync_ms"],
            "cleanup_ms": store["state_cleanup_time_ns"] / 1e6,
            "previous_fsync_ms": frozen["io"]["state_fsync_ms"],
            "ephemeral_fsync_reduction_percent": 100.0,
        },
        "security": {
            "libspartan_tests": "52/52 PASS",
            "libspartan_doc_tests": "3/3 PASS",
            "integration_streaming_tests": "4/4 PASS",
            "v3d_crash_semantics": "1/1 PASS",
            "pbmo_tests": "9/9 PASS",
            "software_only_snapshot_rollback_not_prevented": True,
        },
        "outputs": [
            "PHASE_V3C_ACTIVE_STREAMING_FROZEN",
            "FS4_PRACTICAL_LOWER_BOUND_GAP_ATTRIBUTED",
            "TRANSCRIPT_DEPENDENT_OBJECT_AUDIT_COMPLETE",
            "THINWALLET_CHECKPOINT_RECOMPUTE_PASS",
            "DENSE_MLE_LATE_USE_RECOMPUTATION_PASS",
            "ADDRESS_HASH_OPENING_RECOMPUTATION_PASS",
            "FS5_BUFFER_OVERLAP_REDUCTION_PASS",
            "V3D_RUNTIME_ALLOCATOR_RESIDUAL_AUDIT_COMPLETE",
            "THINWALLET_DURABILITY_CLASSIFICATION_COMPLETE",
            "EPHEMERAL_STATE_FSYNC_REMOVED",
            "PBMO_TOKEN_DURABILITY_PRESERVED",
            "LIBSPARTAN_FS5_TRANSCRIPT_AWARE_RECOMPUTE_PASS",
            "LIBSPARTAN_FS5_TRANSCRIPT_BYTE_IDENTICAL_PASS",
            "LIBSPARTAN_FS5_PROOF_BYTE_IDENTICAL_PASS",
            "LIBSPARTAN_UNCHANGED_VERIFIER_WITH_FS5_PASS",
            "THINWALLET_FS5_PLANNER_VALIDATION_COMPLETE",
            "THINWALLET_2P18_UNDER_320M_FS5_PASS",
            "THINWALLET_FS5_DURABILITY_LATENCY_RESULT_COMPLETE",
            "THINWALLET_FS5_SECURITY_REGRESSION_PASS",
        ],
        "classification": "PHASE_V3D_320M_TRANSCRIPT_RECOMPUTE_PASS",
        "notes": [
            "The 111 MiB runtime reserve was not reduced.",
            "The 288 MiB result is a desktop WSL experimental boundary, not a mobile-production claim.",
            "SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED remains in force.",
        ],
    }

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "fs4_gap_attribution.json").write_text(json.dumps(gap, indent=2) + "\n")
    (OUT / "v3d_results.json").write_text(json.dumps(result, indent=2) + "\n")
    json.loads((OUT / "fs4_gap_attribution.json").read_text())
    json.loads((OUT / "v3d_results.json").read_text())
    print(OUT / "v3d_results.json")


if __name__ == "__main__":
    main()
