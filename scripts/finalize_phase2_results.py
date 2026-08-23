#!/usr/bin/env python3
"""Finalize exact Phase-2 acceptance fields from existing raw observations."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def first_mismatch(left: list[Any], right: list[Any]) -> int | None:
    for index, (left_value, right_value) in enumerate(zip(left, right)):
        if left_value != right_value:
            return index
    return None if len(left) == len(right) else min(len(left), len(right))


def rng_commitment(seed: int) -> str:
    return hashlib.sha256(
        b"thinwallet-experiment-rng" + seed.to_bytes(8, "big")
    ).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--summary-root", default="results/summary")
    parser.add_argument("--pbmo-server-log", required=True)
    args = parser.parse_args()

    matrix_path = Path(args.matrix)
    matrix = load(matrix_path)
    runs = [row for row in matrix["randomized_execution_order"] if row["measured"]]
    server_line = Path(args.pbmo_server_log).read_text(encoding="utf-8").splitlines()[0]
    endpoint = json.loads(server_line)["listen"]
    by_seed: dict[int, dict[str, Path]] = {}
    for row in runs:
        by_seed.setdefault(row["seed"], {})[row["mode"]] = Path(row["run_directory"])

    compatibility = []
    errors = []
    for seed, paths in sorted(by_seed.items()):
        native_root = paths["native"]
        native_proof = load(native_root / "proof.json")
        native_transcript = jsonl(native_root / "transcript_audit.jsonl")
        native_commitments = jsonl(native_root / "commitments_audit.jsonl")
        native_unblinded = [
            record for record in native_commitments
            if record["blinded_or_unblinded"] == "unblinded"
        ]
        native_blinded = [
            record for record in native_commitments
            if record["blinded_or_unblinded"] == "blinded"
        ]
        for mode, root in sorted(paths.items()):
            manifest_path = root / "manifest.json"
            manifest = load(manifest_path)
            config = manifest["effective_configuration"]
            pbmo = bool(config["pbmo_enabled"])
            memory = bool(config["external_sumcheck_folding"])
            config.update(
                {
                    "experiment_mode": mode,
                    "local_native_commitment_enabled": not pbmo,
                    "external_sumcheck_folding_enabled": memory,
                    "selective_spilling_enabled": memory,
                    "recomputation_enabled": memory,
                    "lifetime_scheduling_enabled": memory,
                    "opening_fusion_enabled": memory,
                    "pbmo_server_endpoint": endpoint if pbmo else None,
                    "instrumentation_enabled": True,
                }
            )
            manifest.update(
                {
                    "rng_implementation": (
                        "Merlin RandomTape initialized from Scalar::from(u64 seed)"
                    ),
                    "rng_seed_commitment": rng_commitment(seed),
                    "rng_seed_commitment_domain": "thinwallet-experiment-rng",
                    "rng_seed_canonical_encoding": "unsigned 64-bit big-endian",
                    "rng_bytes_consumed_or_null": None,
                    "rng_stream_digest_or_null": None,
                }
            )
            write(manifest_path, manifest)

            proof_path = root / "proof.json"
            proof = load(proof_path)
            transcript = jsonl(root / "transcript_audit.jsonl")
            commitments = jsonl(root / "commitments_audit.jsonl")
            unblinded = [
                record for record in commitments
                if record["blinded_or_unblinded"] == "unblinded"
            ]
            blinded = [
                record for record in commitments
                if record["blinded_or_unblinded"] == "blinded"
            ]
            proof_length_equal = proof["proof_length"] == native_proof["proof_length"]
            proof_bytes_equal = (
                proof_length_equal
                and proof["proof_sha256"] == native_proof["proof_sha256"]
            )
            transcript_mismatch = first_mismatch(native_transcript, transcript)
            commitment_mismatch = first_mismatch(native_commitments, commitments)
            unblinded_mismatch = first_mismatch(native_unblinded, unblinded)
            blinded_mismatch = first_mismatch(native_blinded, blinded)
            proof.update(
                {
                    "proof_bytes_equal_to_native": proof_bytes_equal,
                    "proof_length_equal_to_native": proof_length_equal,
                    "verifier_result_equal_to_native": (
                        proof["verifier_result"] == native_proof["verifier_result"]
                    ),
                    "transcript_equal_to_native": transcript_mismatch is None,
                    "first_transcript_mismatch_index_or_null": transcript_mismatch,
                    "unblinded_commitments_equal_to_native": unblinded_mismatch is None,
                    "blinded_commitments_equal_to_native": blinded_mismatch is None,
                    "ordered_commitments_equal_to_native": commitment_mismatch is None,
                    "first_unblinded_commitment_mismatch_index_or_null": (
                        unblinded_mismatch
                    ),
                    "first_blinded_commitment_mismatch_index_or_null": blinded_mismatch,
                    "first_commitment_mismatch_index_or_null": commitment_mismatch,
                }
            )
            write(proof_path, proof)

            summary = load(root / "summary.json")
            counters = summary["backend_result"]["execution_counters"]
            network = load(root / "network.json")
            memory_counters = (
                counters["spill_files_created"],
                counters["external_fold_rounds"],
                counters["recomputed_objects"],
                counters["opening_fusions"],
            )
            mode_ok = (
                (
                    mode == "native"
                    and counters["pbmo_sessions_started"] == 0
                    and counters["aggregate_checks_executed"] == 0
                    and counters["native_commitment_calls"] > 0
                    and all(value == 0 for value in memory_counters)
                )
                or (
                    mode == "pbmo-only"
                    and counters["pbmo_sessions_started"] > 0
                    and counters["pbmo_sessions_completed"]
                    == counters["pbmo_sessions_started"]
                    and counters["aggregate_checks_passed"]
                    == counters["aggregate_checks_executed"]
                    and counters["native_commitment_calls"] == 0
                    and all(value == 0 for value in memory_counters)
                )
                or (
                    mode == "memory-only"
                    and counters["pbmo_sessions_started"] == 0
                    and counters["native_commitment_calls"] > 0
                    and any(value > 0 for value in memory_counters)
                )
                or (
                    mode == "full"
                    and counters["pbmo_sessions_started"] > 0
                    and counters["pbmo_sessions_completed"]
                    == counters["pbmo_sessions_started"]
                    and counters["aggregate_checks_passed"]
                    == counters["aggregate_checks_executed"]
                    and counters["native_commitment_calls"] == 0
                    and any(value > 0 for value in memory_counters)
                )
            )
            if not mode_ok:
                errors.append({"seed": seed, "mode": mode, "error": "mode_assertion"})
            row = {
                "workload": manifest["workload"],
                "seed": seed,
                "mode": mode,
                "proof_length": proof["proof_length"],
                "proof_sha256": proof["proof_sha256"],
                "proof_bytes_equal_to_native": proof_bytes_equal,
                "proof_length_equal_to_native": proof_length_equal,
                "verifier_result_equal_to_native": proof[
                    "verifier_result_equal_to_native"
                ],
                "transcript_event_count": proof["transcript_event_count"],
                "transcript_audit_sha256": proof["transcript_sha256"],
                "transcript_equal_to_native": proof["transcript_equal_to_native"],
                "first_transcript_mismatch_index_or_null": transcript_mismatch,
                "ordered_commitment_count": proof["ordered_commitment_count"],
                "ordered_commitments_sha256": proof["ordered_commitments_sha256"],
                "unblinded_commitments_equal_to_native": (
                    proof["unblinded_commitments_equal_to_native"]
                ),
                "blinded_commitments_equal_to_native": (
                    proof["blinded_commitments_equal_to_native"]
                ),
                "ordered_commitments_equal_to_native": (
                    proof["ordered_commitments_equal_to_native"]
                ),
                "first_commitment_mismatch_index_or_null": commitment_mismatch,
                "verifier_result": proof["verifier_result"],
                "verifier_is_unmodified": proof["verifier_is_unmodified"],
                "upload_bytes": network["upload_bytes"],
                "download_bytes": network["download_bytes"],
                "run_directory": str(root),
            }
            compatibility.append(row)

    fields = list(compatibility[0])
    target = Path(args.summary_root) / "compatibility.csv"
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(compatibility)
    acceptance = {
        "schema_version": "thinwallet-experiment-v1",
        "status": "success" if not errors else "failed",
        "measured_runs": len(compatibility),
        "all_proof_bytes_equal": all(
            row["proof_bytes_equal_to_native"] for row in compatibility
        ),
        "all_transcripts_equal": all(
            row["transcript_equal_to_native"] for row in compatibility
        ),
        "all_unblinded_commitments_equal": all(
            row["unblinded_commitments_equal_to_native"] for row in compatibility
        ),
        "all_blinded_commitments_equal": all(
            row["blinded_commitments_equal_to_native"] for row in compatibility
        ),
        "all_verifiers_accept": all(row["verifier_result"] for row in compatibility),
        "all_verifiers_unmodified": all(
            row["verifier_is_unmodified"] for row in compatibility
        ),
        "errors": errors,
        "unavailable_metrics": [
            "Merlin internal sponge state digest",
            "RNG bytes consumed",
            "RNG stream digest",
            "complete logical temporary bytes written",
            "Android battery, charging, and ambient temperature on WSL",
            "Git commit/dirty metadata because the workspace is not a Git checkout",
        ],
    }
    write(Path(args.summary_root) / "phase2_acceptance.json", acceptance)
    print(json.dumps(acceptance, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
