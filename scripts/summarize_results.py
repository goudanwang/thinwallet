#!/usr/bin/env python3
"""Summarize ThinWallet Phase-2 raw bundles without inventing missing values."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def phase_peaks(run_dir: Path, common: dict[str, Any]) -> list[dict[str, Any]]:
    path = run_dir / "memory.csv"
    if not path.is_file():
        return []
    peaks: dict[str, dict[str, int | None]] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            phase = row.get("active_phase") or ""
            if not phase:
                continue
            target = peaks.setdefault(
                phase, {"rss_peak_bytes": None, "pss_peak_bytes": None, "sample_count": 0}
            )
            target["sample_count"] = int(target["sample_count"] or 0) + 1
            for source, destination in (
                ("vmrss_bytes", "rss_peak_bytes"),
                ("pss_bytes", "pss_peak_bytes"),
            ):
                value = row.get(source)
                if value and value != "null":
                    parsed = int(value)
                    prior = target[destination]
                    target[destination] = parsed if prior is None else max(int(prior), parsed)
    return [{**common, "phase": phase, **values} for phase, values in sorted(peaks.items())]


def summarize(args: argparse.Namespace) -> int:
    matrix = read_json(Path(args.matrix))
    measured = [row for row in matrix["randomized_execution_order"] if row["measured"]]
    run_rows: list[dict[str, Any]] = []
    peak_rows: list[dict[str, Any]] = []
    compatibility_rows: list[dict[str, Any]] = []
    for order in measured:
        run_dir = Path(order["run_directory"])
        summary = read_json(run_dir / "summary.json")
        manifest = read_json(run_dir / "manifest.json")
        proof = read_json(run_dir / "proof.json")
        network = read_json(run_dir / "network.json")
        temp = read_json(run_dir / "temp_storage.json")
        backend = summary["backend_result"]
        counters = backend["execution_counters"]
        common = {
            "seed": order["seed"],
            "mode": order["mode"],
            "order": order["order"],
            "run_directory": str(run_dir),
        }
        run_rows.append(
            {
                **common,
                "status": summary["status"],
                "exit_status": summary["exit_status"],
                "wall_ms": summary["wall_ns"] / 1_000_000,
                "process_cpu_ms": summary["process_cpu_ns"] / 1_000_000,
                "prove_ms": backend["prove_ms"],
                "peak_rss_mb": backend["peak_rss_mb"],
                "proof_bytes": proof["proof_length"],
                "upload_bytes": network.get("upload_bytes"),
                "download_bytes": network.get("download_bytes"),
                "temp_peak_bytes": temp.get("temp_peak_bytes"),
                "source_tree_sha256": manifest["source_tree_sha256"],
                "cargo_lock_sha256": manifest["cargo_lock_sha256"],
                "binary_sha256": manifest["binary_sha256"],
                **counters,
            }
        )
        peak_rows.extend(phase_peaks(run_dir, common))
        compatibility_rows.append(
            {
                **common,
                "proof_length": proof["proof_length"],
                "proof_sha256": proof["proof_sha256"],
                "proof_equal_to_native": proof["proof_bytes_equal_to_native"],
                "transcript_event_count": proof["transcript_event_count"],
                "transcript_sha256": proof["transcript_sha256"],
                "transcript_equal_to_native": proof["transcript_equal_to_native"],
                "ordered_commitment_count": proof["ordered_commitment_count"],
                "ordered_commitments_sha256": proof["ordered_commitments_sha256"],
                "commitments_equal_to_native": proof[
                    "ordered_commitments_equal_to_native"
                ],
                "unchanged_native_verifier_accepts": proof["verifier_result"],
                "verifier_is_unmodified": proof["verifier_is_unmodified"],
            }
        )

    summary_root = Path(args.summary_root)
    run_fields = [
        "seed", "mode", "order", "status", "exit_status", "wall_ms",
        "process_cpu_ms", "prove_ms", "peak_rss_mb", "proof_bytes",
        "upload_bytes", "download_bytes", "temp_peak_bytes", *(
            "native_commitment_calls native_commitment_rows pbmo_sessions_started "
            "pbmo_sessions_completed pbmo_rows_uploaded pbmo_server_outputs_received "
            "aggregate_checks_executed aggregate_checks_passed spill_files_created "
            "external_fold_rounds recomputed_objects opening_fusions"
        ).split(),
        "source_tree_sha256", "cargo_lock_sha256", "binary_sha256", "run_directory",
    ]
    write_csv(summary_root / "phase2_runs.csv", run_rows, run_fields)
    write_csv(
        summary_root / "phase_peaks.csv",
        peak_rows,
        [
            "seed", "mode", "order", "phase", "sample_count",
            "rss_peak_bytes", "pss_peak_bytes", "run_directory",
        ],
    )
    write_csv(
        summary_root / "compatibility.csv",
        compatibility_rows,
        [
            "seed", "mode", "order", "proof_length", "proof_sha256",
            "proof_equal_to_native", "transcript_event_count", "transcript_sha256",
            "transcript_equal_to_native", "ordered_commitment_count",
            "ordered_commitments_sha256", "commitments_equal_to_native",
            "unchanged_native_verifier_accepts", "verifier_is_unmodified",
            "run_directory",
        ],
    )

    overhead_path = Path(args.overhead)
    overhead_rows = []
    if overhead_path.is_file():
        overhead = read_json(overhead_path)
        overhead_rows = overhead["records"]
        for row in overhead_rows:
            row["wall_ms"] = row["wall_ns"] / 1_000_000
            row["process_cpu_ms"] = row["process_cpu_ns"] / 1_000_000
        write_csv(
            summary_root / "instrumentation_overhead.csv",
            overhead_rows,
            [
                "instrumentation", "measured", "exit_status", "wall_ms",
                "process_cpu_ms", "proof_length", "proof_sha256",
                "verifier_result", "run_directory",
            ],
        )
    else:
        write_csv(
            summary_root / "instrumentation_overhead.csv",
            [],
            [
                "instrumentation", "measured", "exit_status", "wall_ms",
                "process_cpu_ms", "proof_length", "proof_sha256",
                "verifier_result", "run_directory",
            ],
        )
    print(
        json.dumps(
            {
                "measured_runs": len(run_rows),
                "phase_peak_rows": len(peak_rows),
                "compatibility_rows": len(compatibility_rows),
                "overhead_rows": len(overhead_rows),
                "summary_root": str(summary_root.resolve()),
            },
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--overhead", required=True)
    parser.add_argument("--summary-root", default="results/summary")
    return summarize(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
