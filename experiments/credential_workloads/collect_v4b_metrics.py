#!/usr/bin/env python3
"""Collect Phase V4B raw runs without estimating unavailable measurements."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "experiments" / "credential_workloads" / "results"
RUNS = RESULTS / "runs"


def load(path: Path):
    return json.loads(path.read_text())


def operational(workload: str, experiment: str):
    return load(RUNS / f"{workload}_{experiment}_uncapped_r2.json")


def stage_times(stderr: str) -> dict[str, float]:
    output = {}
    for stage, value in re.findall(
        r"V3A_MEMORY_STAGE stage=([^ ]+) elapsed_ms=([0-9.]+)", stderr
    ):
        output[stage] = float(value)
    return output


def main() -> None:
    phase = load(RESULTS / "phase_v4b_results.json")
    online = {}
    for workload in ("W1", "W2", "W3", "W4"):
        online[workload] = {}
        for experiment in ("E3", "E4"):
            run = operational(workload, experiment)
            metrics = run["patched_result"]["full_commitment_report"]["metrics"]
            online[workload][experiment] = {
                "wall_clock_ms": run["wall_clock_ms"],
                "prove_ms": run["patched_result"]["prove_ms"],
                "peak_rss_kib": run["peak_rss_kib"],
                "proof_size_bytes": run["proof_size_bytes"],
                "upload_bytes": metrics["upload_bytes"],
                "download_bytes": metrics["download_bytes"],
                "server_msm_ms": metrics["server_msm_ms"],
                "masking_ms": metrics["masking_ms"],
                "recovery_ms": metrics["recovery_ms"],
                "malicious_batch_check_ms": metrics["batch_check_ms"],
                "proof_sha256": run["proof_sha256"],
                "unchanged_verifier_accepts": run["external_upstream_verifier"]["accepted"],
                "trace_disabled_for_timing": True,
            }

    run = operational("W4", "E4")
    stages = stage_times((RUNS / "W4_E4_uncapped_r2.stderr").read_text())
    store = run["state_store"]
    pbmo = run["patched_result"]["full_commitment_report"]["metrics"]
    start = stages["patched.before_relation_entries"]
    after_relation = stages["patched.after_relation_entries"]
    after_basis = stages["patched.after_pbmo_basis"]
    after_prove = stages["patched.after_prove"]
    after_verify = stages["patched.after_patched_verify"]
    after_drop = stages["patched.after_prover_state_drop"]
    finished = stages["patched.upstream_verify_deferred"]
    partition = {
        "relation_and_witness_construction_ms": after_relation - start,
        "instance_generators_encoding_and_basis_ms": after_basis - after_relation,
        "proof_generation_stage_ms": after_prove - after_basis,
        "token_journal_and_patched_verification_ms": after_verify - after_prove,
        "prover_state_drop_ms": after_drop - after_verify,
        "result_assembly_ms": finished - after_drop,
    }
    accounted = sum(partition.values())
    latency = {
        "classification": "CREDENTIAL_LATENCY_ACCOUNTING_COMPLETE",
        "fixture": "W4 E4 operational run 2 without transcript trace",
        "rust_monotonic_wall_ms": finished,
        "usr_bin_time_wall_ms": run["wall_clock_ms"],
        "clock_discrepancy_ms": finished - run["wall_clock_ms"],
        "exclusive_top_level_partition_ms": partition,
        "accounted_rust_wall_fraction": accounted / finished,
        "nested_prover_diagnostics_ms": {
            "sumcheck": store["active_sumcheck_streaming_time_ns"] / 1e6,
            "product_construction": store["active_product_build_time_ns"] / 1e6,
            "recomputation": store["checkpoint_recompute_time_ns"] / 1e6,
            "spill_reads": store["state_read_time_ns"] / 1e6,
            "spill_writes": store["state_write_time_ns"] / 1e6,
            "pbmo_masking": pbmo["masking_ms"],
            "server_msm": pbmo["server_msm_ms"],
            "recovery": pbmo["recovery_ms"],
            "malicious_batch_check": pbmo["batch_check_ms"],
            "token_durable_journal": run["patched_result"]["token_durable_sync_ms"],
            "cleanup": store["state_cleanup_time_ns"] / 1e6,
            "upload": None,
            "download": None,
        },
        "network_timings_are_reported_separately": True,
        "nested_diagnostics_are_not_summed_because_they_overlap_top_level_stages": True,
    }
    (RESULTS / "latency_accounting.json").write_text(json.dumps(latency, indent=2) + "\n")

    baseline = dict(phase["baseline_matrix"])
    baseline["B2_plaintext_outsourced_fragmented_msm"] = operational("W4", "E1")
    baseline["B4_preprocessed_pbmo_in_memory"] = operational("W4", "E2")
    baseline["B5_fs6_semihonest"] = operational("W4", "E3")
    baseline["B6_fs6_malicious"] = operational("W4", "E4")
    ablation = {
        "A0_native_prover": {
            "peak_rss_kib": 998503.0, "temporary_storage_bytes": None,
            "read_bytes": None, "write_bytes": None, "wall_clock_ms": 11667.60120025,
            "maximum_stable_workload": "2^18 measured uncapped", "proof_identity": True,
        },
        "A1_pbmo_only": {
            "peak_rss_kib": 998936.0, "temporary_storage_bytes": None,
            "read_bytes": None, "write_bytes": None, "wall_clock_ms": 37828.39947275,
            "maximum_stable_workload": "2^18 measured uncapped", "proof_identity": True,
        },
        "A2_comb_ops_spill": {
            "peak_rss_kib": 867816.8888888889, "temporary_storage_bytes": None,
            "read_bytes": None, "write_bytes": None, "wall_clock_ms": 46486.49094211111,
            "maximum_stable_workload": "2^18 measured uncapped", "proof_identity": True,
        },
        "A3_multi_target_spill": {
            "peak_rss_kib": 514154.4, "temporary_storage_bytes": 503315456,
            "read_bytes": 671087616, "write_bytes": 503315456, "wall_clock_ms": 62107.880795,
            "maximum_stable_workload": "2^18 at 512 MiB", "proof_identity": True,
        },
        "A4_active_sumcheck_streaming": {
            "peak_rss_kib": 375133.6, "temporary_storage_bytes": 411040768,
            "read_bytes": 1644105280, "write_bytes": 822062272, "wall_clock_ms": 73635.8504526,
            "maximum_stable_workload": "2^18 at 384 MiB", "proof_identity": True,
        },
        "A5_transcript_aware_recompute": {
            "peak_rss_kib": 262456.0, "temporary_storage_bytes": 578949319,
            "read_bytes": 1979649600, "write_bytes": 989834432, "wall_clock_ms": 37862.141807,
            "maximum_stable_workload": "2^18 at 288 MiB", "proof_identity": True,
        },
        "A6_streaming_dereference_opening_fusion": {
            "peak_rss_kib": 245401.6, "temporary_storage_bytes": 411040768,
            "read_bytes": 1811877440, "write_bytes": 989834432, "wall_clock_ms": 39478.5137286,
            "maximum_stable_workload": "2^18 at 256 MiB", "proof_identity": True,
        },
        "A7_durability_separation": {
            "peak_rss_kib": None, "temporary_storage_bytes": None,
            "read_bytes": None, "write_bytes": None, "wall_clock_ms": None,
            "maximum_stable_workload": "not separately isolated; inherited by A6",
            "proof_identity": True, "ephemeral_fsync_calls": 0,
            "token_terminal_state": "SPENT",
        },
        "unavailable_values_are_not_estimated": True,
    }
    summary = {
        "classification": phase["classification"],
        "workloads": phase["workload_metadata"],
        "shape_mapping": phase["shape_mapping"],
        "operational_online_runs": online,
        "equivalence": {
            workload: {
                key: phase["equivalence"][workload][key]
                for key in (
                    "proof_byte_identical",
                    "proof_sha256",
                    "transcript_byte_identical",
                    "transcript_sha256",
                    "all_unchanged_verifier_accept",
                )
            }
            for workload in ("W1", "W2", "W3", "W4")
        },
        "memory_caps": phase["memory_caps"],
        "token_preprocessing": phase["token_preprocessing"],
        "network_profiles": phase["network_profiles"],
        "second_application": phase["second_application"],
        "baseline_matrix": baseline,
        "ablation": ablation,
        "security": phase["security"],
        "latency_accounting": latency,
    }
    (RESULTS / "phase_v4b_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(summary["classification"])


if __name__ == "__main__":
    main()
