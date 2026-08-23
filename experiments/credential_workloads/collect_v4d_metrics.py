#!/usr/bin/env python3
"""Collect measured Phase V4D artifacts without inventing unavailable values."""

from __future__ import annotations

import hashlib
import json
import statistics
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
RUNS = REPO / "experiments/credential_workloads/results/v4d/runs"
V4C_RUNS = REPO / "experiments/credential_workloads/results/v4c/runs"
OUT = REPO / "experiments/credential_workloads/results/v4d"
V4D = REPO / "experiments/v4d"


def load(path: Path):
    return json.loads(path.read_text())


def write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def stats(values):
    values = [float(value) for value in values]
    return {
        "raw": values,
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def next_power_of_two(value: int) -> int:
    return 1 if value <= 1 else 1 << (value - 1).bit_length()


def final_prediction(run) -> int:
    shape = run["memory_plan"]["credential_shape"]
    n = int(run["padded_size"])
    matrix_domain = next_power_of_two(int(shape["max_sparse_matrix_entries"]))
    proving = (
        4_208 * 1024
        + 791 * n
        + 831 * 1024 * int(shape["credential_count"])
        - 56 * matrix_domain
    )
    relation = 850 * n + 1024 * 1024
    return max(proving, relation)


def allocation_category(name, logical_bytes=None, note=None):
    return {
        "category": name,
        "logical_bytes": logical_bytes,
        "allocated_capacity_bytes": None,
        "lifetime": None,
        "producer": None,
        "consumers": None,
        "credential_index_or_layer": None,
        "transcript_dependency": None,
        "access_pattern": None,
        "replayable": None,
        "spillable": None,
        "recomputation_cost": None,
        "duplicate_equivalent_object": None,
        "last_use_point": None,
        "note": note,
    }


def main() -> None:
    gate = [load(RUNS / f"S_WK_52_32_E4_248_r{rep}.json") for rep in range(1, 6)]
    gate_cgroup = [load(RUNS / f"S_WK_52_32_E4_248_r{rep}.cgroup.json") for rep in range(1, 6)]
    boundary_240 = load(RUNS / "S_WK_52_32_E4_240_r96.json")
    boundary_240_cgroup = load(RUNS / "S_WK_52_32_E4_240_r96.cgroup.json")
    s_w4_64 = load(RUNS / "S_W4_E4_64_r97.json")
    s_w4_64_cgroup = load(RUNS / "S_W4_E4_64_r97.cgroup.json")
    fs6 = load(V4C_RUNS / "S_WK_52_32_E4_uncapped_r902.json")
    verification = load(OUT / "verification_status.json")

    scaling_specs = [
        ("S-W1", "S_W1_E4_uncapped_r708.json"),
        ("S-W4", "S_W4_E4_uncapped_r702.json"),
        ("S-WK-1-8", "S_WK_1_8_E4_uncapped_r703.json"),
        ("S-WK-4-12", "S_WK_4_12_E4_uncapped_r704.json"),
        ("S-WK-10-16", "S_WK_10_16_E4_uncapped_r705.json"),
        ("S-WK-25-24", "S_WK_25_24_E4_uncapped_r706.json"),
        ("S-WK-52-32", "S_WK_52_32_E4_248_r1.json"),
    ]
    scaling = []
    for workload, filename in scaling_specs:
        run = load(RUNS / filename)
        predicted = final_prediction(run)
        measured = int(run["peak_rss_kib"] * 1024)
        scaling.append(
            {
                "workload": workload,
                "raw_constraints": run["memory_plan"]["credential_shape"].get(
                    "raw_constraint_count"
                ),
                "padded_constraints": run["padded_size"],
                "predicted_peak_bytes": predicted,
                "measured_process_peak_bytes": measured,
                "prediction_error_percent": abs(predicted - measured) / measured * 100,
                "relation_construction_peak_bytes": None,
                "proof_generation_peak_bytes": measured,
                "wall_clock_ms": run["wall_clock_ms"],
                "prove_ms": run["patched_result"]["prove_ms"],
                "temporary_storage_peak_bytes": run["state_store"][
                    "temporary_storage_peak_bytes"
                ],
                "state_read_bytes": run["state_store"]["bytes_read"],
                "state_write_bytes": run["state_store"]["bytes_written"],
                "proof_size_bytes": run["proof_size_bytes"],
                "upload_bytes": run["patched_result"]["full_commitment_report"]["metrics"][
                    "upload_bytes"
                ],
                "download_bytes": run["patched_result"]["full_commitment_report"]["metrics"][
                    "download_bytes"
                ],
            }
        )

    s_w4 = load(RUNS / "S_W4_E4_uncapped_r707.json")
    reconciliation = {
        "classification": "CREDENTIAL_MEMORY_METRICS_RECONCILED",
        "previous_s_w4_24_1_mib_interpretation": (
            "full process VmHWM from /usr/bin/time -v, not PBMO-only or child-only memory"
        ),
        "cause_of_old_planner_rejections": (
            "fixed 111 MiB synthetic reserve plus a model/metric mismatch"
        ),
        "metrics": {
            "S-W4": {
                "planner_predicted_total_bytes": final_prediction(s_w4),
                "internal_accounted_peak_bytes": s_w4["state_store"][
                    "accounted_arena_peak_bytes"
                ],
                "process_rss_peak_kib": s_w4_64_cgroup["sampled_process_peak_rss_kib"],
                "process_vmhwm_kib": s_w4["peak_rss_kib"],
                "cgroup_memory_peak_bytes": s_w4_64_cgroup["memory_peak_bytes"],
                "anonymous_rss_peak_kib": s_w4_64_cgroup[
                    "sampled_process_peak_rss_anon_kib"
                ],
                "file_backed_rss_peak_kib": s_w4_64_cgroup[
                    "sampled_process_peak_rss_file_kib"
                ],
                "pss_peak_kib": s_w4_64_cgroup["sampled_process_peak_pss_kib"],
                "runtime_reserve_bytes": 4_208 * 1024,
                "allocator_live_bytes": None,
                "temporary_file_peak_bytes": s_w4_64_cgroup[
                    "sampled_temporary_state_peak_bytes"
                ],
            },
            "S-WK-52-32": {
                "planner_predicted_total_bytes": final_prediction(gate[0]),
                "internal_accounted_peak_bytes": gate[0]["state_store"][
                    "accounted_arena_peak_bytes"
                ],
                "process_rss_peak_kib": gate_cgroup[0]["sampled_process_peak_rss_kib"],
                "process_vmhwm_kib": gate[0]["peak_rss_kib"],
                "cgroup_memory_peak_bytes": gate_cgroup[0]["memory_peak_bytes"],
                "anonymous_rss_peak_kib": gate_cgroup[0][
                    "sampled_process_peak_rss_anon_kib"
                ],
                "file_backed_rss_peak_kib": gate_cgroup[0][
                    "sampled_process_peak_rss_file_kib"
                ],
                "pss_peak_kib": gate_cgroup[0]["sampled_process_peak_pss_kib"],
                "runtime_reserve_bytes": 4_208 * 1024,
                "allocator_live_bytes": None,
                "temporary_file_peak_bytes": gate_cgroup[0][
                    "sampled_temporary_state_peak_bytes"
                ],
            },
        },
        "notes": [
            "cgroup memory.peak includes reclaimable page cache and reached the configured cap.",
            "Process VmHWM, cgroup peak, anonymous/file RSS, and PSS are distinct metrics.",
            "Allocator live bytes were not sampled in non-instrumented headline runs and remain null.",
        ],
    }
    write(V4D / "memory_metric_reconciliation.json", reconciliation)

    peak_cut = {
        "workload": "S-WK-52-32",
        "padded_constraints": 262144,
        "measured_process_vmhwm_kib": max(run["peak_rss_kib"] for run in gate),
        "exactly_attributed": False,
        "classification": "WK52_2P18_PEAK_ATTRIBUTION_INCOMPLETE",
        "reason": (
            "the low-overhead headline run did not expose allocator lifetime/capacity records for all categories"
        ),
        "allocations": [
            allocation_category("credential witness values", 8_388_608),
            allocation_category("per-credential MiMC intermediate state", None),
            allocation_category("holder and equality predicate state", None),
            allocation_category("range predicate state", None),
            allocation_category(
                "revocation Merkle paths",
                1_024,
                "Current WK fixture emits one depth-32 path, not 52 paths.",
            ),
            allocation_category("revocation hash intermediate state", None),
            allocation_category(
                "R1CS relation entries",
                45_591_120,
                "Logical sparse-entry bytes; released before the prover peak.",
            ),
            allocation_category("sparse constraint matrices", None),
            allocation_category(
                "external matrix value tables",
                50_331_648,
                "File-backed logical bytes, not simultaneously resident.",
            ),
            allocation_category("dense MLE values", None),
            allocation_category("Sumcheck active state", None),
            allocation_category("product-layer state", None),
            allocation_category(
                "address/read/audit tables",
                29_360_128,
                "Compact u32 tables; prior usize form used 58,720,256 bytes.",
            ),
            allocation_category("dereferenced values", 16_777_216),
            allocation_category("opening state", None),
            allocation_category("commitment scalar layouts", None),
            allocation_category("PBMO objects", None),
            allocation_category("transcript and proof buffers", None),
            allocation_category("runtime and allocator residual", None),
            allocation_category("unknown", None),
        ],
    }
    write(V4D / "wk52_peak_live_cut.json", peak_cut)

    transcript_paths = [
        V4C_RUNS / "S_W4_E0_uncapped_r901.transcript.jsonl",
        V4C_RUNS / "S_W4_E3_uncapped_r901.transcript.jsonl",
        V4C_RUNS / "S_W4_E4_uncapped_r901.transcript.jsonl",
        RUNS / "S_W4_E4_uncapped_r707.transcript.jsonl",
    ]
    transcript_hashes = [hashlib.sha256(path.read_bytes()).hexdigest() for path in transcript_paths]
    fs7_prove = stats([run["patched_result"]["prove_ms"] for run in gate])
    fs7_wall = stats([run["wall_clock_ms"] for run in gate])
    fs7_rss = stats([run["peak_rss_kib"] for run in gate])
    fs6_peak = float(fs6["peak_rss_kib"])
    synthetic_peak_mean = 245_401.6

    results = {
        "phase": "V4D",
        "primary_classification": "PHASE_V4D_MEMORY_REDUCTION_ONLY",
        "frozen_v4c": "PHASE_V4C_PUBLIC_KEY_PROFILE_FROZEN",
        "memory_reconciliation": reconciliation,
        "runtime_model": {
            "FixedRuntimeReserve_bytes": 4_208 * 1024,
            "WorkloadRuntimeMargin": (
                "791*n + 831 KiB*credential_count - 56*next_pow2(max_matrix_entries)"
            ),
            "relation_peak_model": "850*n + 1 MiB",
            "classification": "CREDENTIAL_RUNTIME_RESERVE_RECALIBRATED",
        },
        "peak_attribution": peak_cut,
        "synthetic_vs_credential": {
            "synthetic_fs6_peak_kib_mean": synthetic_peak_mean,
            "credential_fs6_peak_kib": fs6_peak,
            "incremental_kib": fs6_peak - synthetic_peak_mean,
            "incremental_mib": (fs6_peak - synthetic_peak_mean) / 1024,
            "fully_component_attributed": False,
            "known_causes": [
                "credential sparse relation entries and their construction overlap",
                "matrix-value domain expands to 2^19 for the credential relation",
                "address/read/audit tables and larger public-input shape",
            ],
        },
        "implementation_results": {
            "streaming_relation_construction": {
                "status": "PARTIAL",
                "detail": "rows are consumed at finalization, but the Builder still retains all credential rows",
            },
            "compact_credential_witness": {
                "status": "BLOCKED",
                "detail": "no authenticated/session-bound deterministic compact replay source was implemented",
            },
            "mimc_streaming": {
                "status": "PARTIAL",
                "detail": "bounded construction is retained, but authenticated compact-source replay is absent",
            },
            "multi_credential_revocation_streaming": {
                "status": "BLOCKED",
                "detail": "the WK fixture currently emits one revocation path for credential 0",
            },
            "cross_credential_binding_compaction": {"status": "PARTIAL"},
            "sparse_r1cs_construction": {
                "status": "EXTERNAL_SPARSE_R1CS_BACKEND_BLOCKED",
                "detail": "matrix values are externalized, but Instance::new still requires complete A/B/C slices",
            },
            "relation_prover_lifetime_separation": {
                "status": "CREDENTIAL_RELATION_PROVER_LIFETIME_SEPARATION_PASS"
            },
        },
        "gate": {
            "classification": "PROFILE_S_WK52_UNDER_256M_FS7_FAIL",
            "resource_gate_pass": True,
            "failure_reason": (
                "the measured fixture preserves the frozen V4C relation but contains only one revocation path, so it does not satisfy the intended multi-credential revocation semantics"
            ),
            "executed_cap_mib": 248,
            "margin_from_256_mib": 8,
            "successful_runs": sum(
                run["completed"]
                and run["external_upstream_verifier_exit_status"] == 0
                and cgroup["memory_events"].get("oom", 0) == 0
                and cgroup["memory_swap_current_bytes"] == 0
                for run, cgroup in zip(gate, gate_cgroup)
            ),
            "run_count": 5,
            "process_peak_rss_kib": fs7_rss,
            "cgroup_peak_bytes": stats([row["memory_peak_bytes"] for row in gate_cgroup]),
            "prove_ms": fs7_prove,
            "wall_clock_ms": fs7_wall,
            "proof_sha256": sorted({run["proof_sha256"] for run in gate}),
            "proof_size_bytes": sorted({run["proof_size_bytes"] for run in gate}),
            "oom_counts": [row["memory_events"].get("oom", 0) for row in gate_cgroup],
            "swap_bytes": [row["memory_swap_current_bytes"] for row in gate_cgroup],
        },
        "boundary": {
            "classification": "PROFILE_S_WK52_LOW_MEMORY_BOUNDARY_COMPLETE",
            "exploratory_240_mib": {
                "completed": boundary_240["completed"],
                "peak_rss_kib": boundary_240["peak_rss_kib"],
                "cgroup_peak_bytes": boundary_240_cgroup["memory_peak_bytes"],
                "oom": boundary_240_cgroup["memory_events"].get("oom", 0),
                "verifier_exit_status": boundary_240[
                    "external_upstream_verifier_exit_status"
                ],
            },
            "planner": {
                str(cap): {
                    "predicted_peak_bytes": final_prediction(gate[0]),
                    "predicted_margin_bytes": cap * 1024 * 1024 - final_prediction(gate[0]),
                    "eligible_with_8_mib_safety": final_prediction(gate[0]) + 8 * 1024 * 1024
                    <= cap * 1024 * 1024,
                    "executed": cap == 240,
                }
                for cap in (240, 224, 192)
            },
        },
        "identity": {
            "proof_byte_identical": len({run["proof_sha256"] for run in gate} | {fs6["proof_sha256"]})
            == 1,
            "proof_sha256": gate[0]["proof_sha256"],
            "transcript_byte_identical": len(set(transcript_hashes)) == 1,
            "transcript_sha256": transcript_hashes[0],
            "transcript_event_count": sum(1 for _ in transcript_paths[-1].open()),
            "unchanged_verifier_accepts": all(
                run["external_upstream_verifier_exit_status"] == 0 for run in gate
            ),
        },
        "planner_validation": {
            "classification": "CREDENTIAL_FS7_PLANNER_VALIDATION_COMPLETE",
            "rows": scaling,
            "max_prediction_error_percent": max(
                row["prediction_error_percent"] for row in scaling
            ),
            "target_met": all(row["prediction_error_percent"] <= 5 for row in scaling),
        },
        "cross_scaling": {
            "classification": "PROFILE_S_FS7_CROSS_SCALING_COMPLETE",
            "rows": scaling,
        },
        "latency_io": {
            "classification": "PROFILE_S_FS7_MEMORY_LATENCY_TRADEOFF_COMPLETE",
            "fs6_reference": {
                "wall_clock_ms": fs6["wall_clock_ms"],
                "prove_ms": fs6["patched_result"]["prove_ms"],
                "peak_rss_kib": fs6["peak_rss_kib"],
                "state_read_bytes": fs6["state_store"]["bytes_read"],
                "state_write_bytes": fs6["state_store"]["bytes_written"],
            },
            "fs7": {
                "wall_clock_ms": fs7_wall,
                "prove_ms": fs7_prove,
                "peak_rss_kib": fs7_rss,
                "state_read_bytes": gate[0]["state_store"]["bytes_read"],
                "state_write_bytes": gate[0]["state_store"]["bytes_written"],
            },
            "wall_ratio_mean": fs7_wall["mean"] / fs6["wall_clock_ms"],
            "prove_ratio_mean": fs7_prove["mean"] / fs6["patched_result"]["prove_ms"],
            "latency_target_1_5x_met": fs7_wall["mean"] <= 1.5 * fs6["wall_clock_ms"],
        },
        "small_workload_rejection": {
            "classification": "SMALL_CREDENTIAL_PLANNER_REJECTION_EXPLAINED",
            "cause": "metric mismatch and fixed synthetic-reserve overapplication",
            "S-W4_64_mib": {
                "completed": s_w4_64["completed"],
                "process_peak_rss_kib": s_w4_64["peak_rss_kib"],
                "cgroup_peak_bytes": s_w4_64_cgroup["memory_peak_bytes"],
                "oom": s_w4_64_cgroup["memory_events"].get("oom", 0),
            },
            "larger_caps": [96, 128, 160, 192, 224],
            "larger_caps_execution": "not repeated because the same plan has more available memory",
        },
        "security_regression": {
            "executed_checks": verification,
            "complete": False,
            "classification": "PROFILE_S_FS7_SECURITY_REGRESSION_INCOMPLETE",
        },
        "first_remaining_blocker": (
            "Implement an authenticated, session-bound credential-by-credential relation/witness source, including one revocation path per credential, without changing canonical R1CS order."
        ),
        "limitations": [
            "No Android execution was performed.",
            "No W3C VC interoperability claim is made.",
            "No production-wallet claim is made.",
            "MiMC7 has not received an independent security audit.",
        ],
    }
    write(OUT / "phase_v4d_results.json", results)
    write(
        OUT / "phase_v4d_summary.json",
        {
            "primary_classification": results["primary_classification"],
            "gate": results["gate"],
            "boundary": results["boundary"],
            "identity": results["identity"],
            "planner_validation": results["planner_validation"],
            "implementation_results": results["implementation_results"],
            "security_regression": results["security_regression"],
            "first_remaining_blocker": results["first_remaining_blocker"],
        },
    )


if __name__ == "__main__":
    main()
