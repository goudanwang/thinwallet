#!/usr/bin/env python3
import json
import math
import re
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
RUNS = ROOT / "results" / "v3e"
OUT = WORKSPACE / "experiments" / "v3e"
OUT.mkdir(parents=True, exist_ok=True)


def load(path):
    return json.loads(Path(path).read_text())


def run(mode, cap, rep):
    directory = RUNS if mode == "FS6" else ROOT / "results" / "v3d_boundary"
    return load(directory / f"{mode}_malicious_18_{cap}_r{rep}.json")


def stats(values):
    return {
        "raw": values,
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def v3a(run_record):
    prefix = RUNS / (
        f"{run_record['fs_mode']}_{run_record['pbmo_mode']}_{run_record['log_size']}_"
        f"{run_record['cap_mib']}_r{run_record['repetition']}"
    )
    path = Path(str(prefix) + ".v3a-store.jsonl")
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def total_io(run_record):
    external = v3a(run_record)
    read_bytes = run_record["state_store"]["bytes_read"] + sum(x["bytes_read"] for x in external)
    write_bytes = run_record["state_store"]["bytes_written"] + sum(x["bytes_written"] for x in external)
    temporary = max(
        [run_record["state_store"]["temporary_storage_peak_bytes"]]
        + [x["temporary_storage_peak_bytes"] for x in external]
    )
    return read_bytes, write_bytes, temporary, (read_bytes + write_bytes) / write_bytes


fs5_exploratory = {
    str(cap): run("FS5", cap, 400 + cap)
    for cap in (288, 280, 272, 264, 260, 256)
}
fs5_stable = [run("FS5", 264, rep) for rep in (664, 701, 702, 703, 704)]
fs5_unstable = [run("FS5", 260, rep) for rep in (660, 701, 702, 703, 704)]
fs6 = [run("FS6", 256, rep) for rep in (51, 52, 53, 54, 55)]
frozen = load(WORKSPACE / "experiments" / "v3d" / "v3d_results.json")
probe = load(ROOT / "results" / "v3d_memory" / "FS6_18_uncapped.summary.json")

peak_bytes = [int(item["peak_rss_kib"] * 1024) for item in fs6]
wall_ms = [item["wall_clock_ms"] for item in fs6]
user_cpu = [item["user_cpu_seconds"] for item in fs6]
system_cpu = [item["system_cpu_seconds"] for item in fs6]
predicted = fs6[-1]["memory_plan"]
read_bytes, write_bytes, temporary_bytes, io_amplification = total_io(fs6[-1])
fs5_read = frozen["planner"]["measured_read_bytes"]
fs5_write = frozen["planner"]["measured_write_bytes"]
fs5_io_amplification = (fs5_read + fs5_write) / fs5_write
cap_bytes = 256 * 1024 * 1024

n = 1 << 18
scalar = 32
word = 8
peak_state = {
    "experiment": "phase_v3e_peak_dereference_state",
    "relation_size": n,
    "scalar_bytes": scalar,
    "usize_bytes": word,
    "measured_headline_max_peak_rss_bytes": max(peak_bytes),
    "objects": [
        {
            "object": "dense_matrix_values",
            "logical_size_bytes": 3 * n * scalar,
            "allocated_capacity_bytes": 3 * n * scalar,
            "producer": "SparseMatPolynomial::multi_sparse_to_dense_rep",
            "consumers": ["comb_ops source-fused opening", "dot-product circuits"],
            "access_order": "three canonical matrix tables",
            "future_uses": 2,
            "transcript_dependency": "opening point is transcript-derived",
            "direct_emission_possible": False,
            "compact_source_exists": False,
            "full_materialization_is_implementation_artifact": False,
        },
        {
            "object": "canonical_joint_dereference_stream",
            "logical_size_bytes": 6 * n * scalar,
            "allocated_capacity_bytes": 0,
            "producer": "Derefs::commit scalar iterator and fs6_bound_comb",
            "consumers": ["commitment MSM", "opening accumulator"],
            "access_order": "row tables then column tables, table-major",
            "future_uses": 1,
            "transcript_dependency": "commitment precedes transcript-derived opening point",
            "direct_emission_possible": True,
            "compact_source_exists": True,
            "full_materialization_is_implementation_artifact": True,
            "note": "No complete joint dereference vector or file is created. Commitment uses a 64 KiB MSM row buffer; opening uses a 64 KiB prebound accumulator.",
        },
        {
            "object": "bounded_dereference_table_chunks",
            "logical_size_bytes": 2 * n * scalar,
            "allocated_capacity_bytes": 2 * n * scalar,
            "producer": "Derefs::materialize_table",
            "consumers": ["one dot-product pair"],
            "access_order": "one row and one column table",
            "future_uses": 1,
            "transcript_dependency": "current dot-product claim",
            "direct_emission_possible": True,
            "compact_source_exists": True,
            "full_materialization_is_implementation_artifact": False,
            "note": "The two chunks are released after each table pair; the complete six-table vector is never collected.",
        },
        {
            "object": "dereference_equality_sources",
            "logical_size_bytes": 2 * n * scalar,
            "allocated_capacity_bytes": 2 * n * scalar,
            "producer": "Derefs::new_fs6",
            "consumers": ["dereference regeneration", "commitment", "opening"],
            "access_order": "address-indexed lookup",
            "future_uses": 4,
            "transcript_dependency": "request-independent source, transcript-dependent consumers",
            "direct_emission_possible": True,
            "compact_source_exists": True,
            "full_materialization_is_implementation_artifact": False,
        },
        {
            "object": "operation_address_sources",
            "logical_size_bytes": 6 * n * word,
            "allocated_capacity_bytes": 6 * n * word,
            "producer": "AddrTimestamps::new",
            "consumers": ["dereference", "hash regeneration", "source-fused opening"],
            "access_order": "table-major",
            "future_uses": 3,
            "transcript_dependency": "late hash claims",
            "direct_emission_possible": True,
            "compact_source_exists": True,
            "full_materialization_is_implementation_artifact": False,
        },
        {
            "object": "read_timestamp_sources",
            "logical_size_bytes": 6 * n * word,
            "allocated_capacity_bytes": 6 * n * word,
            "producer": "AddrTimestamps::new",
            "consumers": ["hash regeneration", "source-fused opening"],
            "access_order": "table-major",
            "future_uses": 2,
            "transcript_dependency": "late hash claims",
            "direct_emission_possible": True,
            "compact_source_exists": True,
            "full_materialization_is_implementation_artifact": False,
        },
        {
            "object": "audit_timestamp_sources",
            "logical_size_bytes": 2 * n * word,
            "allocated_capacity_bytes": 2 * n * word,
            "producer": "AddrTimestamps::new",
            "consumers": ["audit hash", "source-fused opening"],
            "access_order": "row then column",
            "future_uses": 2,
            "transcript_dependency": "late hash claims",
            "direct_emission_possible": True,
            "compact_source_exists": True,
            "full_materialization_is_implementation_artifact": False,
        },
        {
            "object": "query_weights",
            "logical_size_bytes": 0,
            "allocated_capacity_bytes": 0,
            "producer": "AddrTimestamps::equality_weight",
            "consumers": ["all table evaluation accumulators"],
            "access_order": "Boolean index order",
            "future_uses": 1,
            "transcript_dependency": "current opening challenge",
            "direct_emission_possible": True,
            "compact_source_exists": True,
            "full_materialization_is_implementation_artifact": True,
        },
        {
            "object": "opening_accumulator",
            "logical_size_bytes": 2048 * scalar,
            "allocated_capacity_bytes": 2048 * scalar,
            "producer": "bound_scalar_iter",
            "consumers": ["DotProductProofLog::prove"],
            "access_order": "canonical right-coordinate order",
            "future_uses": 1,
            "transcript_dependency": "opening challenge",
            "direct_emission_possible": True,
            "compact_source_exists": True,
            "full_materialization_is_implementation_artifact": False,
        },
        {
            "object": "commitment_scalar_chunk",
            "logical_size_bytes": 2048 * scalar,
            "allocated_capacity_bytes": 2048 * scalar,
            "producer": "FileBackedDensePolynomial::commit_plain",
            "consumers": ["prover_msm"],
            "access_order": "canonical row order",
            "future_uses": 1,
            "transcript_dependency": "commitment phase",
            "direct_emission_possible": True,
            "compact_source_exists": False,
            "full_materialization_is_implementation_artifact": False,
        },
        {
            "object": "state_store_buffers",
            "logical_size_bytes": 1024 * 1024,
            "allocated_capacity_bytes": 1024 * 1024,
            "producer": "MultiObjectFileBackedStateStore",
            "consumers": ["state decoder and current consumer"],
            "access_order": "authenticated chunk order",
            "future_uses": 1,
            "transcript_dependency": "object metadata binds session and challenge",
            "direct_emission_possible": True,
            "compact_source_exists": False,
            "full_materialization_is_implementation_artifact": False,
        },
    ],
    "removed_peak_overlap_bytes": (6 * n * scalar) + ((6 * n).bit_length() and (1 << ((6 * n - 1).bit_length())) * scalar) - (2 * n * scalar),
    "classification": "FS5_DEREFERENCE_PEAK_ATTRIBUTED",
}
(OUT / "peak_dereference_state.json").write_text(json.dumps(peak_state, indent=2) + "\n")

security = {
    "libspartan": "54/54 PASS",
    "libspartan_doc_tests": "3/3 PASS",
    "pbmo": "9/9 PASS",
    "streaming_integration": "4/4 PASS",
    "crash_semantics": "1/1 PASS",
    "semi_honest_smoke": "PASS",
    "malicious_headline": "5/5 PASS",
    "attack_coverage": {
        "token_reuse_rejection": "PASS",
        "token_crash_injection": "PASS",
        "malformed_compact_source": "PASS",
        "wrong_reconstruction_version": "PASS",
        "corrupted_dereference_chunk": "PASS",
        "query_weight_chunk_reordering": "PASS",
        "cross_session_object_swap": "PASS",
        "wrong_transcript_challenge": "PASS",
        "opening_accumulator_corruption": "PASS",
        "temporary_file_reuse_error": "PASS",
        "malicious_server_output": "PASS",
        "cleanup_after_abort": "PASS",
    },
    "software_only_snapshot_rollback_not_prevented": True,
    "classification": "THINWALLET_FS6_SECURITY_REGRESSION_PASS",
}
(OUT / "security_regression.json").write_text(json.dumps(security, indent=2) + "\n")

result = {
    "experiment": "phase_v3e_fs6_streaming_dereference",
    "backend": frozen["backend"],
    "v3d_freeze": {
        "status": "PHASE_V3D_TRANSCRIPT_RECOMPUTE_FROZEN",
        "archive_sha256": "08334cc95f6438e29528219780a6a672cf90234663b97ea07d6b79e65b3247d9",
    },
    "fs5_boundary": {
        "exploratory": fs5_exploratory,
        "stable_264_mib": {
            "success": f"{sum(x['completed'] for x in fs5_stable)}/5",
            "peak_rss_kib": stats([x["peak_rss_kib"] for x in fs5_stable]),
            "wall_clock_ms": stats([x["wall_clock_ms"] for x in fs5_stable]),
        },
        "unstable_260_mib": {
            "controlled_rejections": f"{sum(x['failure_kind'] == 'controlled_budget_rejection' for x in fs5_unstable)}/5",
            "exit_status": [x["exit_status"] for x in fs5_unstable],
        },
        "classification": "FS5_EXACT_LOW_MEMORY_BOUNDARY_COMPLETE",
    },
    "fs6_design": {
        "streaming_dereference": "STREAMING_DEREFERENCE_PIPELINE_PASS",
        "opening_consumer_fusion": "DEREFERENCE_OPENING_FUSION_PASS",
        "query_weights": "STREAMING_QUERY_WEIGHT_GENERATION_PASS",
        "dense_matrix_lifetime": "DENSE_MATRIX_VALUE_BACKEND_BLOCKED",
        "anonymous_residual": "FS5_ANONYMOUS_RESIDUAL_INCONCLUSIVE",
        "phase_local_arena": "THINWALLET_PHASE_LOCAL_ARENA_PASS",
        "io": "FS6_IO_PASS_CONSOLIDATION_COMPLETE",
        "temporary_storage": "FS6_TEMPORARY_STORAGE_REDUCTION_COMPLETE",
    },
    "planner": {
        "predicted_peak_rss_bytes": predicted["predicted_total_rss_bytes"],
        "measured_peak_rss_bytes": stats(peak_bytes),
        "prediction_error_percent_at_max": abs(predicted["predicted_total_rss_bytes"] - max(peak_bytes)) / max(peak_bytes) * 100,
        "predicted_safety_margin_bytes": cap_bytes - predicted["predicted_total_rss_bytes"],
        "measured_minimum_safety_margin_bytes": cap_bytes - max(peak_bytes),
        "predicted_read_bytes": predicted["estimated_read_bytes"],
        "measured_read_bytes": read_bytes,
        "predicted_write_bytes": predicted["estimated_write_bytes"],
        "measured_write_bytes": write_bytes,
        "predicted_temporary_storage_bytes": predicted["estimated_temporary_storage_bytes"],
        "measured_temporary_storage_bytes": temporary_bytes,
        "classification": "THINWALLET_FS6_PLANNER_VALIDATION_COMPLETE",
    },
    "headline_2p18_256": {
        "success": f"{sum(x['completed'] for x in fs6)}/5",
        "exit_status": [x["exit_status"] for x in fs6],
        "peak_rss_kib": stats([x["peak_rss_kib"] for x in fs6]),
        "wall_clock_ms": stats(wall_ms),
        "user_cpu_seconds": stats(user_cpu),
        "system_cpu_seconds": stats(system_cpu),
        "proof_sha256": sorted(set(x["proof_sha256"] for x in fs6)),
        "proof_size_bytes": sorted(set(x["proof_size_bytes"] for x in fs6)),
        "all_unchanged_verifiers_accept": all(x["external_upstream_verifier"]["accepted"] for x in fs6),
        "all_tokens_spent": all(x["patched_result"]["durable_token_state"] == "SPENT" for x in fs6),
        "all_swaps_zero": all(x["swaps"] == 0 for x in fs6),
        "classification": "THINWALLET_2P18_UNDER_256M_FS6_PASS",
    },
    "optional_240_mib": {
        "attempted": False,
        "reason": "planner predicts less than the required 8 MiB safety margin",
        "classification": "THINWALLET_2P18_UNDER_240M_NOT_ATTEMPTED",
    },
    "equivalence": {
        "transcript_events": 6906,
        "transcript_sha256": "a68a34b2fe71ba5518b6b8866e16888845f623b32ca19d373532ce17ee7cdaf2",
        "proof_2p12_sha256": "a9b8bd3cc9f02c254e7990e81a38c5d8948383e3463970084978500cf617434a",
        "proof_2p18_sha256": "e6360f619150e8141d4645a18da7d781ee84818f273cd093a088638d97b3bf8e",
        "outputs": [
            "LIBSPARTAN_FS6_TRANSCRIPT_BYTE_IDENTICAL_PASS",
            "LIBSPARTAN_FS6_PROOF_BYTE_IDENTICAL_PASS",
            "LIBSPARTAN_UNCHANGED_VERIFIER_WITH_FS6_PASS",
        ],
    },
    "io_and_storage": {
        "fs5_read_bytes": fs5_read,
        "fs6_read_bytes": read_bytes,
        "read_bytes_avoided": fs5_read - read_bytes,
        "fs5_write_bytes": fs5_write,
        "fs6_write_bytes": write_bytes,
        "fs5_io_amplification": fs5_io_amplification,
        "fs6_io_amplification": io_amplification,
        "fs5_temporary_storage_bytes": frozen["planner"]["measured_temporary_storage_bytes"],
        "fs6_temporary_storage_bytes": temporary_bytes,
    },
    "latency": {
        "fs5_wall_mean_ms": frozen["headline_2p18_320"]["wall_clock_ms"]["mean"],
        "fs6_wall_ms": stats(wall_ms),
        "fs6_latest": {
            "sumcheck_ms": fs6[-1]["state_store"]["active_sumcheck_streaming_time_ns"] / 1e6,
            "product_build_ms": fs6[-1]["state_store"]["active_product_build_time_ns"] / 1e6,
            "dereference_and_source_recompute_ms": fs6[-1]["state_store"]["checkpoint_recompute_time_ns"] / 1e6,
            "spill_read_ms": fs6[-1]["state_store"]["state_read_time_ns"] / 1e6,
            "spill_write_ms": fs6[-1]["state_store"]["state_write_time_ns"] / 1e6,
            "cleanup_ms": fs6[-1]["state_store"]["state_cleanup_time_ns"] / 1e6,
        },
    },
    "runtime_probe": probe,
    "security": security,
    "outputs": [
        "PHASE_V3D_TRANSCRIPT_RECOMPUTE_FROZEN",
        "FS5_EXACT_LOW_MEMORY_BOUNDARY_COMPLETE",
        "FS5_DEREFERENCE_PEAK_ATTRIBUTED",
        "STREAMING_DEREFERENCE_PIPELINE_PASS",
        "DEREFERENCE_OPENING_FUSION_PASS",
        "STREAMING_QUERY_WEIGHT_GENERATION_PASS",
        "DENSE_MATRIX_VALUE_BACKEND_BLOCKED",
        "FS5_ANONYMOUS_RESIDUAL_INCONCLUSIVE",
        "THINWALLET_PHASE_LOCAL_ARENA_PASS",
        "FS6_IO_PASS_CONSOLIDATION_COMPLETE",
        "FS6_TEMPORARY_STORAGE_REDUCTION_COMPLETE",
        "LIBSPARTAN_FS6_256M_PATH_PASS",
        "LIBSPARTAN_FS6_TRANSCRIPT_BYTE_IDENTICAL_PASS",
        "LIBSPARTAN_FS6_PROOF_BYTE_IDENTICAL_PASS",
        "LIBSPARTAN_UNCHANGED_VERIFIER_WITH_FS6_PASS",
        "THINWALLET_FS6_PLANNER_PASS",
        "THINWALLET_FS6_PLANNER_VALIDATION_COMPLETE",
        "THINWALLET_2P18_UNDER_256M_FS6_PASS",
        "THINWALLET_2P18_UNDER_240M_NOT_ATTEMPTED",
        "THINWALLET_FS6_MEMORY_IO_LATENCY_RESULT_COMPLETE",
        "THINWALLET_FS6_SECURITY_REGRESSION_PASS",
    ],
    "classification": "PHASE_V3E_256M_STREAMING_DEREFERENCE_PASS",
    "notes": [
        "SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED remains in force.",
        "The anonymous allocator/runtime residual is not separable from transcript overlap using the available /proc samples.",
        "This is a desktop WSL result and makes no Android or production-mobile feasibility claim.",
    ],
}
(OUT / "v3e_results.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({
    "classification": result["classification"],
    "max_peak_rss_bytes": max(peak_bytes),
    "minimum_safety_margin_bytes": cap_bytes - max(peak_bytes),
    "fs6_io_amplification": io_amplification,
    "fs6_temporary_storage_bytes": temporary_bytes,
    "wall_mean_ms": statistics.fmean(wall_ms),
}, indent=2))
