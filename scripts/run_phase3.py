#!/usr/bin/env python3
"""ThinWallet Phase 3 performance experiment orchestration."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import math
import random
import shutil
import statistics
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "results" / "raw"
SUMMARY = ROOT / "results" / "summary"
WORKLOADS = ("S-W1", "S-W4", "H0", "H1", "H2")
MODES = ("native", "pbmo-only", "memory-only", "full")
SEEDS = (978453202, 978453203, 978453204, 978453205, 978453206)

spec = importlib.util.spec_from_file_location("thinwallet_bench", ROOT / "scripts" / "thinwallet_bench.py")
bench = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bench)


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * fraction
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def stats(values: list[float]) -> dict[str, float | None]:
    return {
        "median": statistics.median(values) if values else None,
        "p25": percentile(values, 0.25),
        "p75": percentile(values, 0.75),
        "min": min(values) if values else None,
        "max": max(values) if values else None,
    }


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def memory_summary(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "memory.csv"
    if not path.is_file():
        summary = read_json(run_dir / "summary.json", {})
        rss = summary.get("external_time_v", {}).get("maximum_resident_set_size_kib")
        return {
            "peak_vmhwm_mib": None if rss is None else rss / 1024,
            "peak_pss_mib": None,
            "peak_vmrss_sampled_mib": None,
            "median_sampled_rss_mib": None,
            "peak_phase": None,
        }
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    numeric = lambda row, name: None if row.get(name) in (None, "", "null") else int(row[name])
    hwm_rows = [(numeric(row, "vmhwm_bytes"), row) for row in rows]
    hwm_rows = [(value, row) for value, row in hwm_rows if value is not None]
    rss = [value for row in rows if (value := numeric(row, "vmrss_bytes")) is not None]
    pss = [value for row in rows if (value := numeric(row, "pss_bytes")) is not None]
    peak = max(hwm_rows, default=(None, {}), key=lambda item: item[0] or 0)
    return {
        "peak_vmhwm_mib": None if peak[0] is None else peak[0] / 2**20,
        "peak_pss_mib": None if not pss else max(pss) / 2**20,
        "peak_vmrss_sampled_mib": None if not rss else max(rss) / 2**20,
        "median_sampled_rss_mib": None if not rss else statistics.median(rss) / 2**20,
        "peak_phase": peak[1].get("active_phase") or None,
    }


def io_summary(run_dir: Path) -> dict[str, Any]:
    rows = list(csv.DictReader((run_dir / "io.csv").open(encoding="utf-8"))) if (run_dir / "io.csv").is_file() else []
    def delta(name: str) -> int | None:
        values = [int(row[name]) for row in rows if row.get(name) not in (None, "", "null")]
        return max(values) - min(values) if values else None
    return {"read_bytes": delta("read_bytes"), "write_bytes": delta("write_bytes")}


def phase_rows(run_dir: Path, workload: str, mode: str, run_id: str) -> list[dict[str, Any]]:
    path = run_dir / "phases.jsonl"
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("event") == "end":
            rows.append({
                "workload": workload,
                "mode": mode,
                "run_id": run_id,
                "phase": event.get("phase"),
                "elapsed_ms": event.get("elapsed_ns_on_end", 0) / 1e6,
                "vmhwm_mib": None if event.get("vmhwm_bytes") is None else event["vmhwm_bytes"] / 2**20,
                "pss_mib": None if event.get("pss_bytes_or_null") is None else event["pss_bytes_or_null"] / 2**20,
                "status": event.get("status"),
            })
    return rows


def args_for(workload: str, mode: str, run_id: str, seed: int, profile: str,
             endpoint: str | None, key: Path | None, timeout_s: float) -> argparse.Namespace:
    return argparse.Namespace(
        experiment_mode=mode,
        workload=workload,
        run_id=run_id,
        device_id="local-wsl-phase3",
        prover_seed=seed,
        workload_seed=0,
        thread_count=1,
        memory_budget_mib=2048,
        pbmo_endpoint=endpoint,
        pbmo_psk_file=None if key is None else str(key),
        experiment_temp_dir=None,
        repo_root=str(ROOT),
        binary=str(ROOT / "experiments/libspartan/target/release/thinwallet_android_bench"),
        server_binary=str(ROOT / "experiments/libspartan/target/release/pbmo_tcp_server"),
        result_root=str(RAW),
        summary_root=str(SUMMARY),
        instrumentation=profile != "off",
        instrumentation_profile=profile,
        allow_unsafe_drvfs=False,
        metrics_sample_ms=250,
        timeout_s=timeout_s,
    )


def run_dir(workload: str, mode: str, run_id: str) -> Path:
    binary = ROOT / "experiments/libspartan/target/release/thinwallet_android_bench"
    description = bench.workload_description(binary, workload, ROOT)
    return RAW / "local-wsl-phase3" / description["canonical_name"] / mode / run_id


def run_one(arguments: argparse.Namespace) -> tuple[int, Path]:
    path = run_dir(arguments.workload, arguments.experiment_mode, arguments.run_id)
    if (path / "summary.json").is_file():
        return int(read_json(path / "summary.json", {}).get("exit_status", 1)), path
    if path.exists():
        shutil.rmtree(path)
    return bench.run_experiment(arguments, quiet=True), path


def build() -> None:
    subprocess.run(
        ["cargo", "build", "--release", "--bin", "thinwallet_android_bench",
         "--bin", "phase_v2_pbmo", "--bin", "pbmo_tcp_server"],
        cwd=ROOT / "experiments/libspartan", check=True,
    )
    subprocess.run(
        ["cargo", "build", "--release", "--bin", "phase3_pbmo_microbench"],
        cwd=ROOT / "experiments/preprocessed-pbmo", check=True,
    )


def overhead(timeout_s: float) -> list[dict[str, Any]]:
    records = []
    server_dir = RAW / "_phase3" / "overhead-server-v4"
    with bench.pbmo_server(
        ROOT,
        ROOT / "experiments/libspartan/target/release/pbmo_tcp_server",
        server_dir,
        20,
    ) as (endpoint, key):
        order = [("off", False), ("perf", False)]
        measured = [("off", True)] * 5 + [("perf", True)] * 5
        random.Random(0x5033).shuffle(measured)
        order.extend(measured)
        for index, (profile, is_measured) in enumerate(order):
            run_id = f"phase3-overhead-v4-{index:02}-{profile}-{'m' if is_measured else 'w'}"
            status, path = run_one(args_for("S-W1", "full", run_id, SEEDS[0], profile, endpoint, key, timeout_s))
            summary = read_json(path / "summary.json", {})
            proof = read_json(path / "proof.json", {})
            memory = memory_summary(path)
            records.append({
                "mode": "full",
                "profile": profile,
                "measured": is_measured,
                "exit_status": status,
                "wall_s": summary.get("wall_ns", 0) / 1e9,
                "cpu_s": summary.get("process_cpu_ns", 0) / 1e9,
                **memory,
                "proof_sha256": proof.get("proof_sha256"),
                "proof_result_equal": None,
                "run_directory": str(path),
            })
    measured_rows = [row for row in records if row["measured"] and row["exit_status"] == 0]
    baseline_hashes = {row["proof_sha256"] for row in measured_rows}
    medians = {}
    for profile in ("off", "perf"):
        group = [row for row in measured_rows if row["profile"] == profile]
        medians[profile] = {
            "wall": statistics.median(row["wall_s"] for row in group) if group else None,
            "cpu": statistics.median(row["cpu_s"] for row in group) if group else None,
            "hwm": statistics.median(row["peak_vmhwm_mib"] for row in group if row["peak_vmhwm_mib"] is not None) if group else None,
            "pss": statistics.median(row["peak_pss_mib"] for row in group if row["peak_pss_mib"] is not None) if any(row["peak_pss_mib"] is not None for row in group) else None,
        }
    output = []
    for profile in ("off", "perf"):
        output.append({
            "mode": "full",
            "profile": profile,
            "runs": len([row for row in measured_rows if row["profile"] == profile]),
            "median_wall_s": medians[profile]["wall"],
            "median_cpu_s": medians[profile]["cpu"],
            "median_vmhwm_mib": medians[profile]["hwm"],
            "median_peak_pss_mib": medians[profile]["pss"],
            "wall_overhead_percent": None if profile == "off" else (medians["perf"]["wall"] / medians["off"]["wall"] - 1) * 100,
            "cpu_overhead_percent": None if profile == "off" else (medians["perf"]["cpu"] / medians["off"]["cpu"] - 1) * 100,
            "proof_result_equal": len(baseline_hashes) == 1,
        })
    write_csv(SUMMARY / "perf_instrumentation_overhead.csv", output)
    return output


def token_preprocessing() -> list[dict[str, Any]]:
    binary = ROOT / "experiments/libspartan/target/release/phase_v2_pbmo"
    rows = []
    for workload in WORKLOADS:
        for count in (1, 5, 10):
            native_dir = Path(tempfile.mkdtemp(prefix=f"thinwallet-token-{workload}-{count}-"))
            try:
                subprocess.run(
                    [str(binary), "token-generate", "--workload", workload, "--count", str(count),
                     "--output-dir", str(native_dir), "--instrumentation-profile", "perf"],
                    cwd=ROOT / "experiments/libspartan", check=True,
                )
                raw_dir = RAW / "token-generation" / workload / f"count-{count}"
                raw_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(native_dir / "token_generation.json", raw_dir / "token_generation.json")
                shutil.copy2(native_dir / "memory.csv", raw_dir / "memory.csv")
                data = read_json(native_dir / "token_generation.json", {})
                for record in data.get("records", []):
                    rows.append({
                        "record_type": "token",
                        "workload": record["workload"],
                        "batch_count": count,
                        "token_index": record["token_index"],
                        "q": record["q"],
                        "m": record["m"],
                        "prf_ms": record["prf_expansion_ns"] / 1e6,
                        "field_reduction_ms": record["field_reduction_ns"] / 1e6,
                        "correction_msm_ms": record["correction_msm_total_ns"] / 1e6,
                        "correction_msm_fraction": record["correction_msm_total_ns"] / record["total_ns"],
                        "serialization_ms": (record["correction_encoding_ns"] + record["metadata_encoding_ns"]) / 1e6,
                        "encryption_ms": record["token_encryption_ns"] / 1e6,
                        "write_ms": record["file_write_ns"] / 1e6,
                        "fsync_ms": record["fsync_ns"] / 1e6,
                        "total_ms": record["total_ns"] / 1e6,
                        "peak_vmhwm_mib": record["peak_vmhwm_kib"] / 1024,
                        "peak_pss_mib": record["pss_after_kib"] / 1024,
                        "token_bytes": record["token_bytes"],
                        "token_state": record["token_state"],
                        "filesystem_type": "tmpfs_or_wsl_native",
                    })
            finally:
                shutil.rmtree(native_dir, ignore_errors=True)
    summary_rows = []
    groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[(row["workload"], row["batch_count"])].append(row)
    for (workload, count), group in groups.items():
        ordered = sorted(group, key=lambda row: row["token_index"])
        totals = stats([row["total_ms"] for row in ordered])
        summary_rows.append({
            "record_type": "summary",
            "workload": workload,
            "batch_count": count,
            "repetitions": len(group),
            "median_total_ms": totals["median"],
            "p25_total_ms": totals["p25"],
            "p75_total_ms": totals["p75"],
            "min_total_ms": totals["min"],
            "max_total_ms": totals["max"],
            "first_total_ms": ordered[0]["total_ms"],
            "tenth_total_ms": ordered[9]["total_ms"] if count == 10 else None,
            "tenth_over_first": ordered[9]["total_ms"] / ordered[0]["total_ms"]
            if count == 10 else None,
        })
    rows.extend(summary_rows)
    write_csv(SUMMARY / "token_preprocessing.csv", rows)
    return rows


def microbench() -> list[dict[str, Any]]:
    binary = ROOT / "experiments/preprocessed-pbmo/target/release/phase3_pbmo_microbench"
    rows = []
    for workload in WORKLOADS:
        description = bench.workload_description(
            ROOT / "experiments/libspartan/target/release/thinwallet_android_bench",
            workload, ROOT,
        )
        q, m = description["metadata"]["q"], description["metadata"]["m"]
        repetitions = 10
        temp_root = Path(tempfile.mkdtemp(prefix=f"thinwallet-micro-{workload}-"))
        raw_path = RAW / "pbmo-microbench" / f"{workload}.json"
        try:
            subprocess.run(
                [str(binary), "--workload", workload, "--q", str(q), "--m", str(m),
                 "--repetitions", str(repetitions), "--output", str(raw_path),
                 "--temp-root", str(temp_root)],
                check=True,
            )
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)
        data = read_json(raw_path, {})
        groups = defaultdict(list)
        hwms = defaultdict(list)
        for sample in data.get("samples", []):
            groups[sample["operation"]].append(sample["elapsed_ns"] / 1e6)
            if sample.get("peak_vmhwm_kib") is not None:
                hwms[sample["operation"]].append(sample["peak_vmhwm_kib"] / 1024)
        for operation, values in groups.items():
            summary = stats(values)
            rows.append({
                "machine": "local-wsl-phase3",
                "workload": workload,
                "q": q,
                "m": m,
                "operation": operation,
                "repetitions": len(values),
                "median_ms": summary["median"],
                "p25": summary["p25"],
                "p75": summary["p75"],
                "min": summary["min"],
                "max": summary["max"],
                "peak_vmhwm_mib": max(hwms[operation]) if hwms[operation] else None,
                "terms": q * m if operation in {"q_native_m_term_msms", "q_m_term_msms", "local_native_commitment_call"} else m,
                "upload_bytes": q * m * 32 if "pbmo" in operation or "server" in operation else 0,
                "download_bytes": q * 32 if "pbmo" in operation or "server" in operation else 0,
            })
    write_csv(SUMMARY / "pbmo_microbench.csv", rows)
    return rows


def four_mode_matrix(timeout_s: float) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows, phases = [], []
    for workload in WORKLOADS:
        schedule = [(None, mode, False) for mode in MODES]
        measured = [(seed, mode, True) for seed in SEEDS for mode in MODES]
        random.Random(0x503300 + sum(map(ord, workload))).shuffle(schedule)
        random.Random(0x503301 + sum(map(ord, workload))).shuffle(measured)
        schedule.extend(measured)
        server_dir = RAW / "_phase3" / f"matrix-server-v2-{workload}"
        with bench.pbmo_server(
            ROOT,
            ROOT / "experiments/libspartan/target/release/pbmo_tcp_server",
            server_dir,
            40,
        ) as (endpoint, key):
            for index, (seed, mode, measured_flag) in enumerate(schedule):
                actual_seed = SEEDS[0] if seed is None else seed
                run_id = f"phase3-matrix-v2-{workload}-{index:02}-{mode}-{'m' if measured_flag else 'w'}-s{actual_seed}"
                status, path = run_one(args_for(workload, mode, run_id, actual_seed, "perf", endpoint, key, timeout_s))
                summary = read_json(path / "summary.json", {})
                network = read_json(path / "network.json", {})
                temp = read_json(path / "temp_storage.json", {})
                backend = read_json(path / "backend_result.json", {})
                memory = memory_summary(path)
                io = io_summary(path)
                report = backend.get("full_commitment_report") or {}
                metrics = report.get("metrics") or {}
                transport = metrics.get("transport_metrics") or {}
                current_phases = phase_rows(path, workload, mode, run_id)
                token_phase_ms = sum(
                    item["elapsed_ms"]
                    for item in current_phases
                    if item["phase"] == "pbmo_token_load"
                ) or None
                transport_total_ms = transport.get("total_ms")
                # Client-observed online latency is the transport's measured
                # end-to-end request duration. Server and network components
                # are reported separately and may overlap this wall interval.
                online_client_ms = transport_total_ms
                rows.append({
                    "record_type": "run",
                    "workload": workload,
                    "mode": mode,
                    "run_id": run_id,
                    "seed": actual_seed,
                    "measured": measured_flag,
                    "success": status == 0,
                    "failure": None if status == 0 else ("timeout" if status == 124 else "error"),
                    "exit_status": status,
                    "wall_s": summary.get("wall_ns", 0) / 1e9,
                    "cpu_s": summary.get("process_cpu_ns", 0) / 1e9,
                    **memory,
                    "temp_peak_mib": None if temp.get("temp_peak_bytes") is None else temp["temp_peak_bytes"] / 2**20,
                    "logical_temp_write_mib": None if temp.get("logical_bytes_written") is None else temp["logical_bytes_written"] / 2**20,
                    "read_gib": None if io["read_bytes"] is None else io["read_bytes"] / 2**30,
                    "write_gib": None if io["write_bytes"] is None else io["write_bytes"] / 2**30,
                    "upload_mib": None if network.get("upload_bytes") is None else network["upload_bytes"] / 2**20,
                    "download_kib": None if network.get("download_bytes") is None else network["download_bytes"] / 2**10,
                    "token_state": read_json(path / "token.json", {}).get("state"),
                    "pbmo_online_client_ms": online_client_ms,
                    "pbmo_server_ms": metrics.get("server_msm_ms"),
                    "network_ms": sum(transport.get(key, 0) for key in ("connect_ms", "upload_ms", "download_ms")),
                    "token_generation_time_ms": token_phase_ms,
                    "pbmo_total_client_time_ms": None
                    if online_client_ms is None else online_client_ms + (token_phase_ms or 0),
                    "pbmo_total_system_time_ms": None
                    if transport_total_ms is None
                    else transport_total_ms
                    + (token_phase_ms or 0)
                    + (metrics.get("server_msm_ms") or 0),
                    "run_directory": str(path),
                })
                phases.extend(current_phases)
    summaries = []
    for workload in WORKLOADS:
        for mode in MODES:
            group = [
                row for row in rows
                if row["workload"] == workload
                and row["mode"] == mode
                and row["measured"]
            ]
            successful = [row for row in group if row["success"]]
            wall = stats([row["wall_s"] for row in successful])
            cpu = stats([row["cpu_s"] for row in successful])
            hwm = stats([row["peak_vmhwm_mib"] for row in successful if row["peak_vmhwm_mib"] is not None])
            pss = stats([row["peak_pss_mib"] for row in successful if row["peak_pss_mib"] is not None])
            summaries.append({
                "record_type": "summary",
                "workload": workload,
                "mode": mode,
                "repetitions": len(group),
                "successful_runs": len(successful),
                "failed_runs": len(group) - len(successful),
                "median_wall_s": wall["median"],
                "p25_wall_s": wall["p25"],
                "p75_wall_s": wall["p75"],
                "min_wall_s": wall["min"],
                "max_wall_s": wall["max"],
                "median_cpu_s": cpu["median"],
                "p25_cpu_s": cpu["p25"],
                "p75_cpu_s": cpu["p75"],
                "min_cpu_s": cpu["min"],
                "max_cpu_s": cpu["max"],
                "median_peak_vmhwm_mib": hwm["median"],
                "p25_peak_vmhwm_mib": hwm["p25"],
                "p75_peak_vmhwm_mib": hwm["p75"],
                "min_peak_vmhwm_mib": hwm["min"],
                "max_peak_vmhwm_mib": hwm["max"],
                "median_peak_pss_mib": pss["median"],
            })
    phase_summaries = []
    phase_groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in phases:
        phase_groups[(row["workload"], row["mode"], row["phase"])].append(row)
    for (workload, mode, phase), group in phase_groups.items():
        elapsed = stats([row["elapsed_ms"] for row in group])
        hwm = stats([row["vmhwm_mib"] for row in group if row["vmhwm_mib"] is not None])
        phase_summaries.append({
            "record_type": "summary",
            "workload": workload,
            "mode": mode,
            "phase": phase,
            "repetitions": len(group),
            "median_elapsed_ms": elapsed["median"],
            "p25_elapsed_ms": elapsed["p25"],
            "p75_elapsed_ms": elapsed["p75"],
            "min_elapsed_ms": elapsed["min"],
            "max_elapsed_ms": elapsed["max"],
            "median_vmhwm_mib": hwm["median"],
        })
    for row in phases:
        row["record_type"] = "run"
    rows.extend(summaries)
    phases.extend(phase_summaries)
    write_csv(SUMMARY / "four_mode_comparison_phase3.csv", rows)
    write_csv(SUMMARY / "phase3_phase_peaks.csv", phases)
    return rows, phases


def compatibility(timeout_s: float) -> list[dict[str, Any]]:
    rows = []
    for workload in WORKLOADS:
        paths = {}
        server_dir = RAW / "_phase3" / f"compat-server-v2-{workload}"
        with bench.pbmo_server(
            ROOT,
            ROOT / "experiments/libspartan/target/release/pbmo_tcp_server",
            server_dir,
            10,
        ) as (endpoint, key):
            for index, mode in enumerate(MODES):
                run_id = f"phase3-compat-v2-{workload}-{index:02}-{mode}"
                status, path = run_one(args_for(workload, mode, run_id, SEEDS[0], "audit", endpoint, key, timeout_s))
                paths[mode] = path
                rows.append({"workload": workload, "mode": mode, "exit_status": status, "run_directory": str(path)})
        try:
            if not all(
                row["exit_status"] == 0
                for row in rows
                if row["workload"] == workload
            ):
                comparison = {}
            else:
                comparison = bench.apply_native_comparison(paths)
        except (OSError, KeyError, TypeError, ValueError):
            comparison = {}
        for row in rows:
            if row["workload"] == workload:
                result = comparison.get(row["mode"], {})
                row.update({
                    "proof_equal": result.get("proof_equal"),
                    "transcript_equal": result.get("transcript_equal"),
                    "commitments_equal": result.get("commitments_equal"),
                    "verifier_accepts": result.get("verifier_accepts"),
                })
    write_csv(SUMMARY / "all_workload_compatibility.csv", rows)
    return rows


def temp_accounting(matrix_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for row in matrix_rows:
        if row.get("record_type", "run") != "run":
            continue
        path = Path(row["run_directory"])
        data = read_json(path / "temp_artifacts.json", {})
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for artifact in data.get("artifacts", []):
            grouped[artifact.get("category", "miscellaneous")].append(artifact)
        for category in (
            "sumcheck_spill",
            "opening_spill",
            "pbmo_request_spool",
            "pbmo_response_spool",
            "token_file",
            "miscellaneous",
        ):
            grouped.setdefault(category, [])
        for category, artifacts in grouped.items():
            output.append({
                "workload": row["workload"],
                "mode": row["mode"],
                "run_id": row["run_id"],
                "category": category,
                "artifact_count": len(artifacts),
                "bytes_written_logical": sum(item.get("bytes_written_logical", 0) for item in artifacts),
                "final_logical_size": sum(item.get("final_logical_size", 0) for item in artifacts),
                "peak_logical_size": sum(item.get("peak_logical_size", 0) for item in artifacts),
                "allocated_size_if_available": sum(item.get("allocated_size_if_available") or 0 for item in artifacts),
                "create_count": sum(item.get("create_count", 0) for item in artifacts),
                "write_count": sum(item.get("write_count", 0) for item in artifacts),
                "truncate_count": sum(item.get("truncate_count", 0) for item in artifacts),
                "remove_count": sum(item.get("remove_count", 0) for item in artifacts),
            })
    write_csv(SUMMARY / "temp_artifact_accounting.csv", output)
    return output


def acceptance(overhead_rows: list[dict[str, Any]], token_rows: list[dict[str, Any]],
               micro_rows: list[dict[str, Any]], matrix_rows: list[dict[str, Any]],
               compatibility_rows: list[dict[str, Any]], artifact_rows: list[dict[str, Any]]) -> None:
    perf = next((row for row in overhead_rows if row["profile"] == "perf"), {})
    perf_overhead = perf.get("wall_overhead_percent")
    if isinstance(perf_overhead, str):
        perf_overhead = float(perf_overhead) if perf_overhead else None
    proof_equal = perf.get("proof_result_equal")
    if isinstance(proof_equal, str):
        proof_equal = proof_equal.lower() == "true"
    token_workloads = {row["workload"] for row in token_rows}
    expected_token_workloads = {
        bench.workload_description(
            ROOT / "experiments/libspartan/target/release/thinwallet_android_bench",
            workload,
            ROOT,
        )["canonical_name"]
        for workload in WORKLOADS
    }
    conditions = {
        "profiles_off_perf_audit_implemented": True,
        "perf_proof_equal": proof_equal is True,
        "perf_wall_overhead_measured": perf_overhead is not None,
        "perf_wall_overhead_at_most_10_percent": perf_overhead is not None and perf_overhead <= 10,
        "vmhwm_primary_metric_present": any(row.get("peak_vmhwm_mib") is not None for row in matrix_rows),
        "pss_metric_present": any(row.get("peak_pss_mib") is not None for row in matrix_rows),
        "pbmo_spool_directly_accounted": any(row.get("category") == "pbmo_request_spool" for row in artifact_rows),
        "token_counts_1_5_10_measured": {int(row["batch_count"]) for row in token_rows} == {1, 5, 10},
        "all_verified_workloads_token_measured": expected_token_workloads.issubset(token_workloads),
        "all_microbench_operations_present": len({row["operation"] for row in micro_rows}) >= 21,
        "four_mode_matrix_rows_retained": len(matrix_rows) >= len(WORKLOADS) * len(MODES) * 6,
        "timeouts_retained_as_rows": True,
        "compatibility_audit_all_workloads": all(
            str(row.get("exit_status")) == "0"
            and str(row.get("proof_equal")).lower() == "true"
            and str(row.get("transcript_equal")).lower() == "true"
            and str(row.get("commitments_equal")).lower() == "true"
            and str(row.get("verifier_accepts")).lower() == "true"
            for row in compatibility_rows
        ),
        "phase4_not_entered": True,
        "android_energy_thermal_unavailable": True,
    }
    result = {
        "schema_version": "thinwallet-phase3-acceptance-v1",
        "status": "PASS" if all(conditions.values()) else "PARTIAL",
        "conditions": conditions,
        "unavailable": [
            "Android energy and thermal measurements",
            "Android multi-device replication",
            "trusted EMSM baseline",
            "full snapshot rollback prevention",
        ],
    }
    (SUMMARY / "phase3_acceptance.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-s", type=float, default=300)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--sections", default="overhead,token,micro,matrix,compat")
    args = parser.parse_args()
    if not args.skip_build:
        build()
    sections = set(args.sections.split(","))
    overhead_rows = overhead(args.timeout_s) if "overhead" in sections else list(csv.DictReader((SUMMARY / "perf_instrumentation_overhead.csv").open()))
    token_rows = token_preprocessing() if "token" in sections else list(csv.DictReader((SUMMARY / "token_preprocessing.csv").open()))
    micro_rows = microbench() if "micro" in sections else list(csv.DictReader((SUMMARY / "pbmo_microbench.csv").open()))
    if "matrix" in sections:
        matrix_rows, _ = four_mode_matrix(args.timeout_s)
    else:
        matrix_rows = list(csv.DictReader((SUMMARY / "four_mode_comparison_phase3.csv").open()))
    compatibility_rows = compatibility(args.timeout_s) if "compat" in sections else list(csv.DictReader((SUMMARY / "all_workload_compatibility.csv").open()))
    artifact_rows = temp_accounting(matrix_rows)
    acceptance(overhead_rows, token_rows, micro_rows, matrix_rows, compatibility_rows, artifact_rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
