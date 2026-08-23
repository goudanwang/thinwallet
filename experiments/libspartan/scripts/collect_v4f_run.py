#!/usr/bin/env python3
"""Normalize one V4F run without inferring unavailable measurements."""

import argparse
import hashlib
import json
import re
from pathlib import Path


def load(path: Path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def timed(stderr: str, label: str):
    match = re.search(rf"^\s*{re.escape(label)}:\s*([0-9.]+)\s*$", stderr, re.M)
    return float(match.group(1)) if match else None


def integer(value):
    return int(value) if isinstance(value, (int, float)) else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("prefix", type=Path)
    parser.add_argument("workload")
    parser.add_argument("mode")
    parser.add_argument("log_size", type=int)
    parser.add_argument("cap")
    parser.add_argument("repetition", type=int)
    parser.add_argument("exit_status", type=int)
    parser.add_argument("wall_ms", type=float)
    parser.add_argument("external_auth_status")
    parser.add_argument("external_auth_ms")
    parser.add_argument("verify_status")
    parser.add_argument("verify_ms")
    args = parser.parse_args()

    prefix = args.prefix
    stderr = Path(str(prefix) + ".stderr").read_text(errors="replace") if Path(str(prefix) + ".stderr").exists() else ""
    proof_path = Path(str(prefix) + ".proof.bin")
    trace_path = Path(str(prefix) + ".transcript.jsonl")
    patched = load(Path(str(prefix) + ".proof.json"))
    plan = load(Path(str(prefix) + ".plan.json"))
    store = load(Path(str(prefix) + ".v3b-store.json"))
    cgroup = load(Path(str(prefix) + ".cgroup.json"))
    verify = load(Path(str(prefix) + ".verify.json"))

    phase_markers = {
        name: float(value)
        for name, value in re.findall(
            r"^V4F_PHASE_LATENCY phase=([a-z0-9_]+) elapsed_ms=([0-9.]+)$", stderr, re.M
        )
    }
    report = (patched or {}).get("full_commitment_report") or {}
    pbmo = report.get("metrics") or {}
    hard_limit = None if args.cap == "uncapped" else int(args.cap) * 1024 * 1024
    predicted = (plan or {}).get("predicted_total_rss_bytes")
    margin = hard_limit - predicted if hard_limit is not None and predicted is not None else None

    verify_status = None if args.verify_status == "null" else int(args.verify_status)
    cgroup_events = (cgroup or {}).get("memory_events")
    if "controlled plan rejection" in stderr:
        result = "CONTROLLED_PLANNER_REJECTION"
    elif re.search(r"\bKilled\b", stderr) or ((cgroup_events or {}).get("oom_kill", 0) > 0):
        result = "OOM_KILLED"
    elif "memory allocation of" in stderr:
        result = "CONTROLLED_ALLOCATION_FAILURE"
    elif args.exit_status == 0 and proof_path.exists() and patched is not None and verify_status == 0 and (verify or {}).get("accepted") is True:
        result = "PASS"
    elif verify_status not in (0, None):
        result = "VERIFIER_REJECTED"
    elif proof_path.exists() and args.exit_status == 0:
        result = "INVALID_PROOF"
    else:
        result = "INFRASTRUCTURE_ERROR"

    def ns_ms(key):
        value = (store or {}).get(key)
        return value / 1_000_000.0 if isinstance(value, int) else None

    def ext(value):
        return None if value == "null" else float(value)

    phase_latency = {
        "credential_source_open_and_authentication": phase_markers.get("credential_source_open_and_authentication"),
        "ed25519_strict_verification": ext(args.external_auth_ms),
        "public_input_preparation": None,
        "witness_generation": phase_markers.get("witness_generation"),
        "relation_construction": phase_markers.get("relation_construction"),
        "instance_finalization": phase_markers.get("instance_finalization"),
        "compact_source_replay": phase_markers.get("compact_source_replay"),
        "mimc_commitment_processing": None,
        "revocation_processing": None,
        "sumcheck": ns_ms("active_sumcheck_streaming_time_ns"),
        "product_layer_proving": ns_ms("active_product_build_time_ns"),
        "transcript_dependent_recomputation": ns_ms("checkpoint_recompute_time_ns"),
        "external_memory_reads": ns_ms("state_read_time_ns"),
        "external_memory_writes": ns_ms("state_write_time_ns"),
        "pbmo_token_reservation": (patched or {}).get("token_durable_sync_ms"),
        "pbmo_masking": pbmo.get("masking_ms"),
        "request_serialization": None,
        "upload": None,
        "server_msm": pbmo.get("server_msm_ms"),
        "download": None,
        "pbmo_correction": pbmo.get("recovery_ms"),
        "malicious_aggregate_check": pbmo.get("batch_check_ms"),
        "proof_assembly": None,
        "upstream_verifier": ext(args.verify_ms),
        "total_prove": (patched or {}).get("prove_ms"),
        "complete_presentation": args.wall_ms,
    }

    resources = {
        "units": {"memory": "bytes", "latency": "milliseconds", "cpu": "seconds", "counts": "events"},
        "planner_predicted_peak_bytes": predicted,
        "planner_predicted_safety_margin_bytes": margin,
        "internal_accounted_peak_bytes": (store or {}).get("accounted_arena_peak_bytes"),
        "process_current_rss_bytes": None,
        "process_vm_hwm_bytes": integer(timed(stderr, "Maximum resident set size (kbytes)" ) * 1024) if timed(stderr, "Maximum resident set size (kbytes)") is not None else None,
        "process_pss_bytes": integer((cgroup or {}).get("sampled_process_peak_pss_kib") * 1024) if (cgroup or {}).get("sampled_process_peak_pss_kib") is not None else None,
        "process_anonymous_rss_bytes": integer((cgroup or {}).get("sampled_process_peak_rss_anon_kib") * 1024) if (cgroup or {}).get("sampled_process_peak_rss_anon_kib") is not None else None,
        "process_file_rss_bytes": integer((cgroup or {}).get("sampled_process_peak_rss_file_kib") * 1024) if (cgroup or {}).get("sampled_process_peak_rss_file_kib") is not None else None,
        "cgroup_memory_current_bytes": (cgroup or {}).get("memory_current_bytes_after_run"),
        "cgroup_memory_peak_bytes": (cgroup or {}).get("memory_peak_bytes"),
        "cgroup_anonymous_peak_bytes": (cgroup or {}).get("sampled_cgroup_peak_anon_bytes"),
        "cgroup_file_peak_bytes": (cgroup or {}).get("sampled_cgroup_peak_file_bytes"),
        "allocator_live_bytes": (store or {}).get("accounted_arena_current_bytes"),
        "allocator_peak_bytes": (store or {}).get("accounted_arena_peak_bytes"),
        "temporary_file_current_bytes": None,
        "temporary_file_maximum_bytes": (cgroup or {}).get("sampled_temporary_state_peak_bytes", (store or {}).get("temporary_storage_peak_bytes")),
        "bytes_read": (store or {}).get("bytes_read"),
        "bytes_written": (store or {}).get("bytes_written"),
        "voluntary_context_switches": integer(timed(stderr, "Voluntary context switches")),
        "involuntary_context_switches": integer(timed(stderr, "Involuntary context switches")),
        "major_page_faults": integer(timed(stderr, "Major (requiring I/O) page faults")),
        "minor_page_faults": integer(timed(stderr, "Minor (reclaiming a frame) page faults")),
        "swap_bytes": integer(timed(stderr, "Swaps") * 4096) if timed(stderr, "Swaps") is not None else None,
        "oom_status": cgroup_events,
    }

    proof = proof_path.read_bytes() if proof_path.exists() else None
    trace = trace_path.read_bytes() if trace_path.exists() else None
    payload = {
        "schema_version": "thinwallet-v4f-resource-v1",
        "provenance_tag": prefix.name.split("_S_WK_", 1)[0],
        "workload": args.workload,
        "mode": args.mode,
        "mode_label": "privacy-insecure diagnostic baseline" if args.mode == "M1" else None,
        "log_size": args.log_size,
        "padded_constraints": 1 << args.log_size,
        "cap_mib": None if args.cap == "uncapped" else int(args.cap),
        "repetition": args.repetition,
        "result": result,
        "exit_status": args.exit_status,
        "external_auth_exit_status": None if args.external_auth_status == "null" else int(args.external_auth_status),
        "external_upstream_verifier_exit_status": verify_status,
        "external_upstream_verifier": verify,
        "proof_size_bytes": len(proof) if proof is not None else None,
        "proof_sha256": hashlib.sha256(proof).hexdigest() if proof is not None else None,
        "transcript_size_bytes": len(trace) if trace is not None else None,
        "transcript_sha256": hashlib.sha256(trace).hexdigest() if trace is not None else None,
        "transcript_event_count": trace.count(b"\n") if trace is not None else None,
        "patched_result": patched,
        "memory_plan": plan,
        "state_store": store,
        "resources": resources,
        "phase_latency_ms": phase_latency,
        "notes": [
            "Null means the current tool did not measure that field directly.",
            "PBMO transport-only replay latency is not complete presentation latency.",
        ],
    }
    Path(str(prefix) + ".json").write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps({key: payload[key] for key in ("workload", "mode", "cap_mib", "repetition", "result", "proof_sha256")}))


if __name__ == "__main__":
    main()
