#!/usr/bin/env python3
"""Apply the frozen V4G expected/safe process model before cgroup startup."""

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from planner.process_memory_v4g import load, predict  # noqa: E402
from planner.cgroup_memory_v4g import budget  # noqa: E402


def paper_name(name):
    match = re.fullmatch(r"S-WK-k(\d+)-r(\d+)-d(\d+)-(.+)", name)
    labels = {"none": "None", "sparse_merkle": "SparseMerkle", "expiry_only": "ExpiryOnly"}
    return f"WK({match[1]},{match[2]},{match[3]},{labels[match[4]]})"


parser = argparse.ArgumentParser()
parser.add_argument("prefix", type=Path)
parser.add_argument("workload")
parser.add_argument("mode")
parser.add_argument("log_size", type=int)
parser.add_argument("cap_mib", type=int)
parser.add_argument("repetition", type=int)
args = parser.parse_args()

audit = json.loads((ROOT / "experiments/credential_workloads/results/v4e/phase_v4e_semantic_audit.json").read_text())
rows = [row for section in ("composition_scaling", "revocation_scaling", "revocation_policy_profiles") for row in audit[section]]
meta = next(row for row in rows if row["workload"] == paper_name(args.workload))
match = re.fullmatch(r"WK\((\d+),(\d+),(\d+),([^)]+)\)", meta["workload"])
point = {
    "workload": meta["workload"], "mode": args.mode,
    "k": int(match[1]), "r": int(match[2]), "d": int(match[3]), "revocation_backend": match[4],
    "raw_constraints": meta["raw_constraints"], "padded_constraints": 1 << args.log_size,
    "sparse_nonzero_entries": meta["sparse_nonzero_entries"], "witness_elements": meta["witness_elements"],
    "public_inputs": meta["public_inputs"], "source_size_bytes": meta["authenticated_source_bytes"],
    "total_path_siblings": meta["path_sibling_count"], "q": meta["q"], "m": meta["m"],
    "max_sparse_matrix_entries": meta["max_sparse_matrix_entries"],
    "token_bytes": meta["pbmo_token_size_bytes"] or 0, "upload_bytes": meta["upload_bytes"] or 0,
}
model = load(ROOT / "planner/models/process_memory_v4g.json")
prediction = predict(model, point)
cgroup = budget(prediction, point)
cap_bytes = args.cap_mib * 1024 * 1024
process_approved = cap_bytes >= prediction["safe_upper_bound_process_vm_hwm_bytes"]
cgroup_approved = cap_bytes >= cgroup["conservative_cgroup_upper_bound_bytes"]
approved = process_approved and cgroup_approved
decision = {
    "model_version": model["model_version"],
    "cgroup_model_version": "cgroup-memory-v4g-1",
    "workload": point["workload"], "mode": args.mode, "cap_mib": args.cap_mib,
    **prediction, **cgroup, "cap_bytes": cap_bytes,
    "process_approved": process_approved, "cgroup_approved": cgroup_approved,
    "approved": approved,
    "process_remaining_margin_bytes": cap_bytes - prediction["safe_upper_bound_process_vm_hwm_bytes"],
    "cgroup_remaining_margin_bytes": cap_bytes - cgroup["conservative_cgroup_upper_bound_bytes"],
}
Path(str(args.prefix) + ".v4g-preflight.json").write_text(json.dumps(decision, indent=2) + "\n")
print(json.dumps(decision))
raise SystemExit(0 if approved else 42)
