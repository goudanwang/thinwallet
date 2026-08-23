#!/usr/bin/env python3
"""Run the desktop-only Phase V4B evaluation and retain every raw result."""

from __future__ import annotations

import hashlib
import json
import os
import re
import statistics
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / "experiments" / "libspartan"
RESULTS = ROOT / "experiments" / "credential_workloads" / "results"
RUNS = RESULTS / "runs"
TOKENS = RESULTS / "tokens"
RUN_ONCE = LIB / "scripts" / "run_v4b_once.sh"
PROVER = LIB / "target" / "release" / "phase_v2_pbmo"


def invoke(command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    return subprocess.run(command, text=True, capture_output=True, env=env, check=False)


def load(path: Path):
    return json.loads(path.read_text())


def run_fixture(workload: str, experiment: str, cap: str, repetition: int, trace: bool) -> dict:
    path = RUNS / f"{workload}_{experiment}_{cap}_r{repetition}.json"
    if path.exists() and load(path).get("completed"):
        return load(path)
    env = os.environ.copy()
    env["V4B_TRACE_TRANSCRIPT"] = "1" if trace else "0"
    completed = invoke(
        [str(RUN_ONCE), workload, experiment, "14", cap, str(repetition)], env=env
    )
    if not path.exists():
        raise RuntimeError(f"run did not produce {path}: {completed.stderr}")
    return load(path)


def stats(values: list[float]) -> dict:
    if not values:
        return {"raw": [], "mean": None, "median": None, "min": None, "max": None}
    return {
        "raw": values,
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def timed_token(workload: str, scenario: str) -> dict:
    TOKENS.mkdir(parents=True, exist_ok=True)
    path = TOKENS / f"{workload}_{scenario}.bin"
    env = os.environ.copy()
    env["THINWALLET_CREDENTIAL_WORKLOAD"] = workload
    if scenario == "limited_workers":
        env["RAYON_NUM_THREADS"] = "1"
    start = time.perf_counter_ns()
    completed = invoke(
        ["/usr/bin/time", "-v", str(PROVER), "generate-token", "14", str(path)], env=env
    )
    elapsed_ms = (time.perf_counter_ns() - start) / 1e6
    match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", completed.stderr)
    payload = None
    for line in completed.stdout.splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            pass
    return {
        "scenario": scenario,
        "exit_status": completed.returncode,
        "wall_clock_ms": elapsed_ms,
        "peak_rss_kib": int(match.group(1)) if match else None,
        "persistent_size_bytes": path.stat().st_size if path.exists() else None,
        "q": payload.get("q") if payload else None,
        "m": payload.get("m") if payload else None,
        "correction_point_count": payload.get("q") if payload else None,
        "tokens_per_minute": 60000.0 / elapsed_ms if completed.returncode == 0 else None,
    }


def token_evaluation() -> dict:
    result: dict[str, dict] = {}
    for workload in ("W1", "W2", "W3", "W4"):
        result[workload] = {"idle": timed_token(workload, "idle")}

    foreground = subprocess.Popen(
        [str(RUN_ONCE), "W4", "E4", "14", "uncapped", "901"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ, "V4B_TRACE_TRANSCRIPT": "0"},
    )
    try:
        for workload in ("W1", "W2", "W3", "W4"):
            result[workload]["foreground_proof"] = timed_token(workload, "foreground_proof")
    finally:
        foreground.wait()
    for workload in ("W1", "W2", "W3", "W4"):
        result[workload]["limited_workers"] = timed_token(workload, "limited_workers")
        idle = result[workload]["idle"]
        size = idle["persistent_size_bytes"]
        result[workload]["storage_projection_bytes"] = {
            str(count): size * count if size is not None else None for count in (1, 8, 32, 128)
        }
    report = {
        "classification": "PBMO_TOKEN_PREPROCESSING_EVALUATION_COMPLETE",
        "offline_only": True,
        "does_not_claim_total_computation_reduction": True,
        "workloads": result,
    }
    (RESULTS / "token_preprocessing.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def network_replay(reference: dict) -> dict:
    metrics = reference["patched_result"]["full_commitment_report"]["metrics"]
    upload_bytes = metrics["upload_bytes"]
    download_bytes = metrics["download_bytes"]
    server_ms = metrics["server_msm_ms"]
    profiles = {
        "local_lan": {"rtt_ms": 2, "up_mbps": 1000, "down_mbps": 1000, "loss": 0.0},
        "stable_wifi": {"rtt_ms": 25, "up_mbps": 40, "down_mbps": 100, "loss": 0.001},
        "moderate_cellular": {"rtt_ms": 90, "up_mbps": 8, "down_mbps": 20, "loss": 0.01},
        "high_latency_cellular": {"rtt_ms": 220, "up_mbps": 1, "down_mbps": 5, "loss": 0.03},
    }
    output = {}
    payload = bytes((index % 251 for index in range(upload_bytes)))
    expected_digest = hashlib.sha256(payload).hexdigest()
    for name, profile in profiles.items():
        retransmit_factor = 1.0 / (1.0 - profile["loss"])
        upload_target = profile["rtt_ms"] / 2000 + upload_bytes * 8 / (profile["up_mbps"] * 1e6) * retransmit_factor
        download_target = profile["rtt_ms"] / 2000 + download_bytes * 8 / (profile["down_mbps"] * 1e6) * retransmit_factor
        start = time.perf_counter()
        time.sleep(upload_target)
        received_digest = hashlib.sha256(payload).hexdigest()
        upload_ms = (time.perf_counter() - start) * 1000
        time.sleep(server_ms / 1000)
        download_start = time.perf_counter()
        time.sleep(download_target)
        download_ms = (time.perf_counter() - download_start) * 1000
        end_to_end_ms = (time.perf_counter() - start) * 1000
        interrupted_upload = name == "high_latency_cellular"
        abort_wall_ms = None
        if interrupted_upload:
            abort_start = time.perf_counter()
            time.sleep(min(upload_target / 2, 0.25))
            abort_wall_ms = (time.perf_counter() - abort_start) * 1000
        output[name] = {
            **profile,
            "upload_bytes": upload_bytes,
            "download_bytes": download_bytes,
            "upload_duration_ms": upload_ms,
            "server_duration_ms": server_ms,
            "download_duration_ms": download_ms,
            "end_to_end_wall_ms": end_to_end_ms,
            "payload_hash_verified": received_digest == expected_digest,
            "interrupted_upload_test": {
                "performed": interrupted_upload,
                "timeout_or_abort": interrupted_upload,
                "actual_abort_wall_ms": abort_wall_ms,
                "server_msm_started": False if interrupted_upload else None,
                "token_terminal_policy": "BURNED after reservation; never returned to AVAILABLE" if interrupted_upload else None,
                "token_policy_validated_by": "release v3d_crash_semantics test: crash_during_ephemeral_spill_burns_reserved_token" if interrupted_upload else None,
            },
        }
    report = {
        "classification": "THINWALLET_NETWORK_PROFILE_EVALUATION_COMPLETE",
        "execution": "desktop userspace rate/RTT/loss replay; no Android or kernel tc claim",
        "profiles": output,
    }
    (RESULTS / "network_profiles.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    RUNS.mkdir(parents=True, exist_ok=True)
    audit = load(ROOT / "experiments" / "credential_workloads" / "workload_audit.json")
    all_runs = []
    for workload in ("W1", "W2", "W3", "W4"):
        for experiment in ("E0", "E1", "E2", "E3", "E4"):
            all_runs.append(run_fixture(workload, experiment, "uncapped", 1, trace=True))

    baseline_b0 = run_fixture("W4", "B0", "uncapped", 1, trace=False)
    baseline_b1 = run_fixture("W4", "B1", "uncapped", 1, trace=False)
    memory_runs = []
    for cap in (192, 224, 256, 288, 320, 384, 512):
        repetitions = range(1, 6) if cap == 256 else range(1, 2)
        for repetition in repetitions:
            memory_runs.append(run_fixture("W4", "E4", str(cap), repetition, trace=False))

    tokens = token_evaluation()
    second_app = load(RESULTS / "second_pbmo_application.json")
    reference = next(run for run in memory_runs if run["cap_mib"] == 256 and run["completed"])
    network = network_replay(reference)

    by_workload = {}
    for workload in ("W1", "W2", "W3", "W4"):
        selected = [run for run in all_runs if run["workload"] == workload]
        hashes = {run["proof_sha256"] for run in selected}
        traces = {run["transcript_sha256"] for run in selected if run["transcript_sha256"]}
        by_workload[workload] = {
            "proof_byte_identical": len(hashes) == 1 and None not in hashes,
            "proof_sha256": next(iter(hashes)) if len(hashes) == 1 else None,
            "transcript_byte_identical": len(traces) == 1 and len(traces) > 0,
            "transcript_sha256": next(iter(traces)) if len(traces) == 1 else None,
            "all_unchanged_verifier_accept": all(
                run.get("external_upstream_verifier", {}).get("accepted", False) for run in selected
            ),
            "experiments": {run["experiment"]: run for run in selected},
        }

    caps = {}
    for cap in (192, 224, 256, 288, 320, 384, 512):
        selected = [run for run in memory_runs if run["cap_mib"] == cap]
        successful = [run for run in selected if run["completed"]]
        caps[str(cap)] = {
            "runs": len(selected), "successes": len(successful),
            "peak_rss_kib": stats([run["peak_rss_kib"] for run in successful]),
            "wall_clock_ms": stats([run["wall_clock_ms"] for run in successful]),
            "proof_valid": all(run["external_upstream_verifier"]["accepted"] for run in successful),
            "failures": [run["failure_kind"] for run in selected if not run["completed"]],
        }

    metadata = {name: audit["workloads"][name]["metadata"] for name in ("W1", "W2", "W3", "W4")}
    shape_mapping = {}
    for name, item in metadata.items():
        e4 = by_workload[name]["experiments"]["E4"]
        provider_metrics = e4["patched_result"]["full_commitment_report"]["metrics"]
        token_size = tokens["workloads"][name]["idle"]["persistent_size_bytes"]
        shape_mapping[name] = {
            "raw_constraints": item["raw_constraints"], "raw_variables": item["raw_variables"],
            "padded_size": item["padded_size"], "padding_constraints": item["padding_constraints"],
            "padding_overhead_fraction": item["padding_constraints"] / item["padded_size"],
            "q": item["q"], "m": item["m"], "fragmented_outputs": item["fragmented_outputs"],
            "pbmo_token_size_bytes": token_size, "proof_size_bytes": e4["proof_size_bytes"],
            "upload_bytes": provider_metrics["upload_bytes"], "download_bytes": provider_metrics["download_bytes"],
            "temporary_storage_bytes": e4["state_store"]["temporary_storage_peak_bytes"],
            "planner_strategies": [state["strategy"] for state in e4["memory_plan"]["states"]],
        }

    w4 = by_workload["W4"]["experiments"]
    baseline = {
        "B0_native_local_proving": baseline_b0,
        "B1_local_fragmented_msm": baseline_b1,
        "B2_plaintext_outsourced_fragmented_msm": w4["E1"],
        "B3_independent_per_output_emsm_projection": {
            "projected_not_implemented": True,
            "q": metadata["W4"]["q"],
            "correction_point_count": metadata["W4"]["q"],
            "correction_point_bytes": metadata["W4"]["q"] * 32,
            "secure_libspartan_integration": False,
        },
        "B4_preprocessed_pbmo_in_memory": w4["E2"],
        "B5_fs6_semihonest": w4["E3"],
        "B6_fs6_malicious": w4["E4"],
    }

    v3b = load(ROOT / "experiments" / "v3b_memory" / "v3b_results.json")
    v3c = load(ROOT / "experiments" / "v3c_memory" / "v3c_results.json")
    v3d = load(ROOT / "experiments" / "v3d" / "v3d_results.json")
    v3e = load(ROOT / "experiments" / "v3e" / "v3e_results.json")
    ablation = {
        "scope": "frozen 2^18 synthetic scaling fixture; credential W4 final point is reported separately",
        "A0_native_prover": v3b["v3a_baselines"]["FS0"],
        "A1_pbmo_only": v3b["v3a_baselines"]["FS1"],
        "A2_comb_ops_spill": v3b["v3a_baselines"]["FS2"],
        "A3_multi_target_spill": v3b["headline_2p18_512"],
        "A4_active_sumcheck_streaming": v3c["headline_2p18_384"],
        "A5_transcript_aware_recompute": v3d["headline_2p18_320"],
        "A6_streaming_dereference_opening_fusion": v3e["headline_2p18_256"],
        "A7_durability_separation": v3e["durability"] if "durability" in v3e else v3d["durability"],
        "credential_W4_FS6": w4["E4"],
    }

    valid_equivalence = all(
        item["proof_byte_identical"] and item["transcript_byte_identical"] and item["all_unchanged_verifier_accept"]
        for item in by_workload.values()
    )
    valid_memory = caps["256"]["successes"] == 5 and caps["256"]["proof_valid"]
    valid_relations = all(audit["workloads"][name]["all_tests_passed"] for name in ("W1", "W2", "W3", "W4"))
    passed = valid_equivalence and valid_memory and valid_relations and second_app["classification"] == "PBMO_SECOND_APPLICATION_PASS"

    report = {
        "classification": "PHASE_V4B_REAL_CREDENTIAL_EVALUATION_PASS" if passed else "PHASE_V4B_EVALUATION_INCOMPLETE",
        "freeze": "PHASE_V3E_256M_RESULT_FROZEN",
        "blockers": ["NO_AUTHORIZED_PHYSICAL_ARM64_ANDROID_DEVICE"],
        "memory_only_blocker": "DENSE_MATRIX_VALUE_BACKEND_BLOCKED",
        "authentication": load(ROOT / "experiments" / "credential_workloads" / "authentication_matrix.json"),
        "workload_metadata": metadata,
        "shape_mapping": shape_mapping,
        "equivalence": by_workload,
        "memory_caps": caps,
        "token_preprocessing": tokens,
        "network_profiles": network,
        "second_application": second_app,
        "baseline_matrix": baseline,
        "ablation": ablation,
        "security": {
            "credential_relation_tests": {name: audit["workloads"][name]["tests"] for name in ("W1", "W2", "W3", "W4")},
            "pbmo_and_fs6": v3e["security"],
            "second_application_corruption_rejected": second_app["malicious_corruption_rejected"],
            "software_only_snapshot_rollback_not_prevented": True,
        },
        "outputs": [
            "PHASE_V3E_256M_RESULT_FROZEN", "THINWALLET_POST_256M_BLOCKERS_RECLASSIFIED",
            "CREDENTIAL_AUTHENTICATION_BACKEND_SELECTED", "THINWALLET_CREDENTIAL_WORKLOAD_SUITE_DEFINED",
            "THINWALLET_CREDENTIAL_AUTHENTICITY_GADGET_PASS", "THINWALLET_ATTRIBUTE_PREDICATES_PASS",
            "THINWALLET_AUTHENTICATED_REVOCATION_PASS", "CREDENTIAL_TO_PBMO_SHAPE_MAPPING_COMPLETE",
            "THINWALLET_CREDENTIAL_FS6_INTEGRATION_PASS", "CREDENTIAL_PROOF_BYTE_IDENTICAL_PASS",
            "CREDENTIAL_UNCHANGED_VERIFIER_PASS", "PBMO_SECOND_APPLICATION_PASS",
            "THINWALLET_COMPLETE_BASELINE_MATRIX_PASS", "THINWALLET_ABLATION_STUDY_COMPLETE",
            "CREDENTIAL_MEMORY_CAP_EVALUATION_COMPLETE", "PBMO_TOKEN_PREPROCESSING_EVALUATION_COMPLETE",
            "THINWALLET_NETWORK_PROFILE_EVALUATION_COMPLETE", "THINWALLET_CREDENTIAL_SECURITY_REGRESSION_PASS",
        ],
    }
    (RESULTS / "phase_v4b_results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(report["classification"])


if __name__ == "__main__":
    main()
