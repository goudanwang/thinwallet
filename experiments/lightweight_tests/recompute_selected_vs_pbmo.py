#!/usr/bin/env python3
"""Recompute Selected versus PBMO-enabled metrics from existing formal data."""

from __future__ import annotations

import csv
import hashlib
import json
import statistics
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FORMAL = ROOT / "experiments/android_phase5f_c/honest_runs.json"
PREP = ROOT / "experiments/pbmo_preprocessing/pbmo_preprocessing_summary.json"
OUTPUT = ROOT / "results/selected_vs_pbmo.csv"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def median(rows: list[dict[str, Any]], key: str) -> float:
    return float(statistics.median(float(row[key]) for row in rows))


def trace_median(rows: list[dict[str, Any]], key: str) -> float:
    return float(statistics.median(float(row["client_trace"][key]) for row in rows))


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def main() -> int:
    formal = json.loads(FORMAL.read_text(encoding="utf-8"))["runs"]
    prep = json.loads(PREP.read_text(encoding="utf-8"))
    prep_rows = prep["rows"]
    output_rows: list[dict[str, Any]] = []
    for workload in ("H1", "H2"):
        selected = [
            row
            for row in formal
            if row["workload"] == workload and row["mode"] == "M2" and not row["warmup"]
        ]
        pbmo = [
            row
            for row in formal
            if row["workload"] == workload and row["mode"] == "M4" and not row["warmup"]
        ]
        if len(selected) != 5 or len(pbmo) != 5:
            raise RuntimeError(f"unexpected formal cell size for {workload}")
        transports = [ROOT / row["raw_directory"] / "pbmo_transport.json" for row in pbmo]
        if not all(path.is_file() for path in transports):
            missing = [relative(path) for path in transports if not path.is_file()]
            raise RuntimeError(f"missing PBMO transport files: {missing}")
        transport_rows = [json.loads(path.read_text(encoding="utf-8")) for path in transports]
        prep_workload = [row for row in prep_rows if row["workload"] == workload]
        if len(prep_workload) != 5:
            raise RuntimeError(f"unexpected provisioning cell size for {workload}")

        selected_wall = median(selected, "total_request_wall_ms") / 1000.0
        pbmo_wall = median(pbmo, "total_request_wall_ms") / 1000.0
        selected_cpu = median(selected, "total_process_cpu_ms") / 1000.0
        pbmo_cpu = median(pbmo, "total_process_cpu_ms") / 1000.0
        selected_pss = max(float(row["peak_pss_mib"]) for row in selected)
        pbmo_pss = max(float(row["peak_pss_mib"]) for row in pbmo)
        selected_vmhwm = max(float(row["vmhwm_mib"]) for row in selected)
        pbmo_vmhwm = max(float(row["vmhwm_mib"]) for row in pbmo)
        token_required = all(
            row["counters"].get("pregenerated_token_load_calls") == 1
            and row["counters"].get("pbmo_token_generation_calls", 0) == 0
            for row in pbmo
        )

        output_rows.append(
            {
                "workload": workload,
                "selected_mode": "M2/Memory-remote/Selected",
                "pbmo_mode": "M4/Full-remote/PBMO-enabled",
                "n_selected": len(selected),
                "n_pbmo": len(pbmo),
                "wall_statistic": "median",
                "selected_wall_s": f"{selected_wall:.9f}",
                "pbmo_wall_s": f"{pbmo_wall:.9f}",
                "delta_pbmo_minus_selected_wall_s": f"{pbmo_wall-selected_wall:.9f}",
                "cpu_statistic": "median process user+system CPU",
                "selected_client_cpu_s": f"{selected_cpu:.9f}",
                "pbmo_client_cpu_s": f"{pbmo_cpu:.9f}",
                "delta_pbmo_minus_selected_cpu_s": f"{pbmo_cpu-selected_cpu:.9f}",
                "memory_statistic": "maximum across measured runs",
                "selected_peak_pss_mib": f"{selected_pss:.9f}",
                "pbmo_peak_pss_mib": f"{pbmo_pss:.9f}",
                "delta_pbmo_minus_selected_pss_mib": f"{pbmo_pss-selected_pss:.9f}",
                "selected_vmhwm_mib": f"{selected_vmhwm:.9f}",
                "pbmo_vmhwm_mib": f"{pbmo_vmhwm:.9f}",
                "delta_pbmo_minus_selected_vmhwm_mib": f"{pbmo_vmhwm-selected_vmhwm:.9f}",
                "selected_are_request_bytes_median": f"{trace_median(selected, 'request_bytes'):.0f}",
                "selected_are_response_bytes_median": f"{trace_median(selected, 'response_bytes'):.0f}",
                "pbmo_are_request_bytes_median": f"{trace_median(pbmo, 'request_bytes'):.0f}",
                "pbmo_are_response_bytes_median": f"{trace_median(pbmo, 'response_bytes'):.0f}",
                "pbmo_upload_bytes_median": f"{statistics.median(row['request_bytes'] for row in transport_rows):.0f}",
                "pbmo_provisioning_wall_s_median": f"{statistics.median(row['preprocessing_wall_s'] for row in prep_workload):.9f}",
                "pbmo_provisioning_peak_pss_mib_max": f"{max(row['peak_pss_mib'] for row in prep_workload):.9f}",
                "pbmo_token_requirement": "preprovisioned token required; one load/run; online generation zero"
                if token_required
                else "formal rows do not uniformly establish preprovisioned-token use",
                "formal_data_path": relative(FORMAL),
                "formal_data_sha256": sha256(FORMAL),
                "pbmo_provisioning_data_path": relative(PREP),
                "pbmo_provisioning_data_sha256": sha256(PREP),
                "pbmo_transport_data_paths": ";".join(relative(path) for path in transports),
                "pbmo_transport_data_sha256": ";".join(sha256(path) for path in transports),
            }
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(output_rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(output_rows)
    print(f"wrote {relative(OUTPUT)} with {len(output_rows)} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
