#!/usr/bin/env python3
"""Reject unsafe FS7 caps before starting the prover or cgroup service."""

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def paper_name(name):
    match = re.fullmatch(r"S-WK-k(\d+)-r(\d+)-d(\d+)-(.+)", name)
    labels = {"none": "None", "sparse_merkle": "SparseMerkle", "expiry_only": "ExpiryOnly"}
    return f"WK({match[1]},{match[2]},{match[3]},{labels[match[4]]})"


def null_resources(predicted, margin):
    fields = ["internal_accounted_peak_bytes", "process_current_rss_bytes", "process_vm_hwm_bytes", "process_pss_bytes", "process_anonymous_rss_bytes", "process_file_rss_bytes", "cgroup_memory_current_bytes", "cgroup_memory_peak_bytes", "cgroup_anonymous_peak_bytes", "cgroup_file_peak_bytes", "allocator_live_bytes", "allocator_peak_bytes", "temporary_file_current_bytes", "temporary_file_maximum_bytes", "bytes_read", "bytes_written", "voluntary_context_switches", "involuntary_context_switches", "major_page_faults", "minor_page_faults", "swap_bytes", "oom_status"]
    result = {key: None for key in fields}
    result.update({"units": {"memory": "bytes", "latency": "milliseconds", "cpu": "seconds", "counts": "events"}, "planner_predicted_peak_bytes": predicted, "planner_predicted_safety_margin_bytes": margin})
    return result


parser = argparse.ArgumentParser()
parser.add_argument("prefix", type=Path); parser.add_argument("workload"); parser.add_argument("mode")
parser.add_argument("log_size", type=int); parser.add_argument("cap_mib", type=int); parser.add_argument("repetition", type=int)
args = parser.parse_args()
audit = json.loads((ROOT / "experiments/credential_workloads/results/v4e/phase_v4e_semantic_audit.json").read_text())
rows = [row for section in ("composition_scaling", "revocation_scaling", "revocation_policy_profiles") for row in audit[section]]
meta = next(row for row in rows if row["workload"] == paper_name(args.workload))
n = 1 << args.log_size; k = int(re.search(r"-k(\d+)-", args.workload).group(1)); r = int(re.search(r"-r(\d+)-", args.workload).group(1))
matrix_domain = 1 << (meta["max_sparse_matrix_entries"] - 1).bit_length()
old_proving = 4208 * 1024 + 791 * n + 831 * 1024 * k - 56 * matrix_domain
old_relation = 850 * n + 1024 * 1024
predicted = max(old_proving, old_relation) - 150 * n - 8 * 891 * 1024 + k * 891 * 1024 + r * 3100 * 1024
predicted = max(predicted, 232 * meta["sparse_nonzero_entries"] + 1024 * 1024)
cap = args.cap_mib * 1024 * 1024; margin = cap - predicted
if margin >= 8 * 1024 * 1024:
    raise SystemExit(0)
phases = ["credential_source_open_and_authentication", "ed25519_strict_verification", "public_input_preparation", "witness_generation", "relation_construction", "instance_finalization", "compact_source_replay", "mimc_commitment_processing", "revocation_processing", "sumcheck", "product_layer_proving", "transcript_dependent_recomputation", "external_memory_reads", "external_memory_writes", "pbmo_token_reservation", "pbmo_masking", "request_serialization", "upload", "server_msm", "download", "pbmo_correction", "malicious_aggregate_check", "proof_assembly", "upstream_verifier", "total_prove", "complete_presentation"]
payload = {
    "schema_version": "thinwallet-v4f-resource-v1", "provenance_tag": args.prefix.name.split("_S_WK_",1)[0],
    "workload": args.workload, "mode": args.mode, "mode_label": None, "log_size": args.log_size,
    "padded_constraints": n, "cap_mib": args.cap_mib, "repetition": args.repetition,
    "result": "CONTROLLED_PLANNER_REJECTION", "exit_status": None, "proof_size_bytes": None,
    "proof_sha256": None, "transcript_size_bytes": None, "transcript_sha256": None,
    "transcript_event_count": None, "patched_result": None,
    "memory_plan": {"model": "V4F frozen sparse/composition/revocation calibration", "predicted_total_rss_bytes": predicted, "required_safety_bytes": 8*1024*1024},
    "state_store": None, "resources": null_resources(predicted, margin),
    "phase_latency_ms": {name: None for name in phases},
    "notes": ["Deterministic preflight rejection; the prover and cgroup service were not started."]
}
Path(str(args.prefix)+".json").write_text(json.dumps(payload,indent=2)+"\n")
print(json.dumps({"workload":args.workload,"mode":args.mode,"cap_mib":args.cap_mib,"repetition":args.repetition,"result":payload["result"],"predicted_peak_bytes":predicted,"margin_bytes":margin}))
raise SystemExit(42)
