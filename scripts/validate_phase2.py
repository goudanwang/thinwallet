#!/usr/bin/env python3
"""Fail-closed validation for a completed ThinWallet Phase-2 matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


TRANSCRIPT_KEYS = {
    "event_index",
    "operation_type",
    "domain_label_hash",
    "input_length",
    "input_sha256",
    "transcript_state_digest_after_event",
    "state_digest_semantics",
}
COMMITMENT_KEYS = {
    "logical_commitment_call_id",
    "output_index",
    "output_count",
    "point_encoding_length",
    "point_sha256",
    "blinded_or_unblinded",
}


def records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", required=True)
    args = parser.parse_args()
    matrix = json.loads(Path(args.matrix).read_text(encoding="utf-8"))
    runs = [row for row in matrix["randomized_execution_order"] if row["measured"]]
    hashes = {"source": set(), "lock": set(), "binary": set(), "proof": set()}
    phases = set()
    errors = []
    for row in runs:
        root = Path(row["run_directory"])
        summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        proof = json.loads((root / "proof.json").read_text(encoding="utf-8"))
        network = json.loads((root / "network.json").read_text(encoding="utf-8"))
        hashes["source"].add(manifest["source_tree_sha256"])
        hashes["lock"].add(manifest["cargo_lock_sha256"])
        hashes["binary"].add(manifest["binary_sha256"])
        hashes["proof"].add(proof["proof_sha256"])
        if (
            summary["status"] != "success"
            or summary["mode_assertion_failures"]
            or not summary["phase_pairs_valid"]
        ):
            errors.append({"run": row, "error": "run_or_mode_assertion"})
        if not all(
            (
                proof["proof_bytes_equal_to_native"],
                proof["transcript_equal_to_native"],
                proof["ordered_commitments_equal_to_native"],
                proof["verifier_result"],
                proof["verifier_is_unmodified"],
            )
        ):
            errors.append({"run": row, "error": "compatibility"})
        if network["status"] == "measured":
            if network["upload_bytes"] != sum(network["request_breakdown"].values()):
                errors.append({"run": row, "error": "upload_breakdown"})
            if network["download_bytes"] != sum(network["response_breakdown"].values()):
                errors.append({"run": row, "error": "download_breakdown"})
        transcript = records(root / "transcript_audit.jsonl")
        commitments = records(root / "commitments_audit.jsonl")
        if any(set(record) != TRANSCRIPT_KEYS for record in transcript):
            errors.append({"run": row, "error": "transcript_sidecar_keys"})
        if any(set(record) != COMMITMENT_KEYS for record in commitments):
            errors.append({"run": row, "error": "commitment_sidecar_keys"})
        phases.update(record["phase"] for record in records(root / "phases.jsonl"))

    if len(runs) != 20 or len({(row["mode"], row["seed"]) for row in runs}) != 20:
        errors.append({"error": "matrix_coverage"})
    for name in ("source", "lock", "binary"):
        if len(hashes[name]) != 1:
            errors.append({"error": f"{name}_hash_not_unique"})
    result = {
        "matrix_status": matrix["status"],
        "measured_runs": len(runs),
        "mode_seed_pairs": len({(row["mode"], row["seed"]) for row in runs}),
        "source_hash_count": len(hashes["source"]),
        "cargo_lock_hash_count": len(hashes["lock"]),
        "binary_hash_count": len(hashes["binary"]),
        "distinct_seed_proof_hashes": len(hashes["proof"]),
        "phase_names": sorted(phases),
        "errors": errors,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if matrix["status"] == "success" and not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
