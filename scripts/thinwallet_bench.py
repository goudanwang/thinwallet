#!/usr/bin/env python3
"""Opt-in ThinWallet Phase-2 experiment runner."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import resource
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


SCHEMA_VERSION = "thinwallet-experiment-v1"
DEFAULT_PROVER_SEED = 978453202
FIXED_WORKLOAD_SEED = 0
PHASE2_SEEDS = (978453202, 978453203, 978453204, 978453205, 978453206)
MEMORY_FLAGS = (
    "LIBSPARTAN_FIXED_STREAMING",
    "LIBSPARTAN_MULTI_TARGET_STREAMING",
    "LIBSPARTAN_ACTIVE_STATE_STREAMING",
    "LIBSPARTAN_TRANSCRIPT_RECOMPUTE",
    "LIBSPARTAN_STREAMING_DEREFERENCE",
    "LIBSPARTAN_CREDENTIAL_STREAMING",
)
COUNTER_NAMES = (
    "native_commitment_calls",
    "native_commitment_rows",
    "pbmo_sessions_started",
    "pbmo_sessions_completed",
    "pbmo_rows_uploaded",
    "pbmo_server_outputs_received",
    "aggregate_checks_executed",
    "aggregate_checks_passed",
    "spill_files_created",
    "external_fold_rounds",
    "recomputed_objects",
    "opening_fusions",
)
MODES = {
    "native": {
        "backend_command": "upstream",
        "pbmo": False,
        "memory_architecture": False,
        "token_lifecycle": False,
        "implementation": "unmodified baseline libspartan prover",
    },
    "pbmo-only": {
        "backend_command": "malicious",
        "pbmo": True,
        "memory_architecture": False,
        "token_lifecycle": True,
        "implementation": "patched prover with malicious PBMO commitment provider",
    },
    "memory-only": {
        "backend_command": "native",
        "pbmo": False,
        "memory_architecture": True,
        "token_lifecycle": False,
        "implementation": "patched prover with native commitment provider and memory architecture",
    },
    "full": {
        "backend_command": "malicious",
        "pbmo": True,
        "memory_architecture": True,
        "token_lifecycle": True,
        "implementation": "patched prover with malicious PBMO and complete memory architecture",
    },
}


def json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def json_read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def seed_commitment(domain: str, seed: int) -> str:
    return hashlib.sha256(f"{domain}\0{seed}".encode()).hexdigest()


def source_tree_hash(root: Path) -> tuple[str, list[str]]:
    selected: list[Path] = []
    roots = (
        root / "experiments" / "libspartan" / "src",
        root / "experiments" / "libspartan" / "vendor" / "spartan-0.9.0" / "src",
        root
        / "experiments"
        / "libspartan"
        / "vendor"
        / "spartan-baseline-testable-0.9.0"
        / "src",
        root / "experiments" / "preprocessed-pbmo" / "src",
        root / "experiments" / "thinwallet-instrumentation" / "src",
    )
    for source_root in roots:
        selected.extend(path for path in source_root.rglob("*.rs") if path.is_file())
    selected.extend(
        path
        for path in (
            root / "experiments" / "libspartan" / "Cargo.toml",
            root / "experiments" / "libspartan" / "Cargo.lock",
            root / "experiments" / "preprocessed-pbmo" / "Cargo.toml",
            root / "experiments" / "thinwallet-instrumentation" / "Cargo.toml",
            root / "scripts" / "thinwallet_bench.py",
            root / "scripts" / "summarize_results.py",
        )
        if path.is_file()
    )
    digest = hashlib.sha256()
    relative_names = []
    for path in sorted(set(selected)):
        relative = path.relative_to(root).as_posix()
        relative_names.append(relative)
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative.encode())
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest(), relative_names


def command_output(command: list[str], cwd: Path) -> str | None:
    try:
        result = subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip()


def git_metadata(root: Path) -> tuple[str | None, bool | None]:
    commit = command_output(["git", "rev-parse", "HEAD"], root)
    if commit is None:
        return None, None
    status = command_output(["git", "status", "--porcelain"], root)
    return commit, None if status is None else bool(status)


def mem_total_bytes() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def cpu_model() -> str | None:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except (OSError, IndexError):
        pass
    return None


def workload_description(binary: Path, workload: str, cwd: Path) -> dict[str, Any]:
    result = subprocess.run(
        [str(binary), "describe-workload", workload],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def effective_configuration(mode_name: str, args: argparse.Namespace) -> dict[str, Any]:
    mode = MODES[mode_name]
    profile = selected_profile(args)
    return {
        "mode": mode_name,
        "backend_command": mode["backend_command"],
        "pbmo_enabled": mode["pbmo"],
        "pbmo_transport": "tcp" if mode["pbmo"] else None,
        "token_lifecycle_enabled": mode["token_lifecycle"],
        "external_sumcheck_folding": mode["memory_architecture"],
        "selective_spilling": mode["memory_architecture"],
        "recomputation": mode["memory_architecture"],
        "lifetime_scheduling": mode["memory_architecture"],
        "opening_fusion": mode["memory_architecture"],
        "memory_flags": list(MEMORY_FLAGS) if mode["memory_architecture"] else [],
        "thread_count": args.thread_count,
        "memory_budget_mib": args.memory_budget_mib if mode["memory_architecture"] else None,
        "instrumentation_enabled": profile != "off",
        "instrumentation_profile": profile,
        "metrics_sample_ms": args.metrics_sample_ms if profile != "off" else None,
    }


def selected_profile(args: argparse.Namespace) -> str:
    explicit = getattr(args, "instrumentation_profile", None)
    if explicit is not None:
        return explicit
    return "audit" if getattr(args, "instrumentation", True) else "off"


def filesystem_info(path: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["findmnt", "-T", str(path), "-n", "-o", "FSTYPE,TARGET"],
        capture_output=True,
        text=True,
    )
    fields = result.stdout.strip().split(maxsplit=1) if result.returncode == 0 else []
    fs_type = fields[0] if fields else None
    mount = fields[1] if len(fields) > 1 else None
    is_drvfs = fs_type in {"9p", "drvfs"} or str(path).startswith("/mnt/")
    return {
        "filesystem_type": fs_type,
        "temp_root_mount": mount,
        "temp_root_is_wsl_native": not is_drvfs,
        "temp_root_is_drvfs": is_drvfs,
    }


def configure_environment(
    args: argparse.Namespace, run_dir: Path, temp_dir: Path, workload: str
) -> tuple[dict[str, str], dict[str, Any]]:
    env = os.environ.copy()
    for name in MEMORY_FLAGS:
        env.pop(name, None)
    for name in (
        "V3A_STATE_DIR",
        "V3B_STATE_DIR",
        "V3B_HARD_LIMIT_BYTES",
        "THINWALLET_TOKEN_STORE_ROOT",
        "THINWALLET_PROOF_OUT",
        "THINWALLET_RESULT_OUT",
        "THINWALLET_PBMO_ENDPOINT",
        "THINWALLET_PBMO_PSK_FILE",
        "THINWALLET_INSTRUMENTATION",
        "THINWALLET_INSTRUMENTATION_PROFILE",
    ):
        env.pop(name, None)

    mode = MODES[args.experiment_mode]
    if mode["memory_architecture"]:
        for name in MEMORY_FLAGS:
            env[name] = "1"
        env["V3B_HARD_LIMIT_BYTES"] = str(args.memory_budget_mib * 1024 * 1024)
        env["V3A_STATE_DIR"] = str(temp_dir / "opening")
        env["V3B_STATE_DIR"] = str(temp_dir / "prover-state")
    if mode["token_lifecycle"]:
        env["THINWALLET_TOKEN_STORE_ROOT"] = str(temp_dir / "token-store")

    env["THINWALLET_CREDENTIAL_WORKLOAD"] = workload
    env["THINWALLET_RESULT_OUT"] = str(run_dir / "backend_result.json")
    env["THINWALLET_PROOF_OUT"] = str(run_dir / "proof.bin")
    env["THINWALLET_PBMO_TRANSPORT"] = "tcp" if mode["pbmo"] else "local"
    if mode["pbmo"]:
        if not args.pbmo_endpoint or not args.pbmo_psk_file:
            raise ValueError(f"{args.experiment_mode} requires --pbmo-endpoint and --pbmo-psk-file")
        env["THINWALLET_PBMO_ENDPOINT"] = args.pbmo_endpoint
        env["THINWALLET_PBMO_PSK_FILE"] = str(Path(args.pbmo_psk_file).resolve())
    env["RAYON_NUM_THREADS"] = str(args.thread_count)
    env["THINWALLET_THREAD_COUNT"] = str(args.thread_count)
    env["THINWALLET_EXPERIMENT_PROVER_SEED"] = str(args.prover_seed)

    profile = selected_profile(args)
    if profile != "off":
        env.update(
            {
                "THINWALLET_INSTRUMENTATION_PROFILE": profile,
                "THINWALLET_EXPERIMENT_RUN_ID": args.run_id,
                "THINWALLET_PHASES_PATH": str(run_dir / "phases.jsonl"),
                "THINWALLET_TRANSCRIPT_AUDIT_PATH": str(
                    run_dir / "transcript_audit.jsonl"
                ),
                "THINWALLET_COMMITMENTS_AUDIT_PATH": str(
                    run_dir / "commitments_audit.jsonl"
                ),
                "THINWALLET_COUNTERS_PATH": str(run_dir / "execution_counters.json"),
                "THINWALLET_MEMORY_CSV_PATH": str(run_dir / "memory.csv"),
                "THINWALLET_IO_CSV_PATH": str(run_dir / "io.csv"),
                "THINWALLET_TEMP_STORAGE_OUT": str(run_dir / "temp_storage.json"),
                "THINWALLET_TEMP_ARTIFACTS_PATH": str(
                    run_dir / "temp_artifacts.json"
                ),
                "THINWALLET_EXPERIMENT_TEMP_DIR": str(temp_dir),
                "THINWALLET_METRICS_SAMPLE_MS": str(args.metrics_sample_ms),
            }
        )

    enabled = {
        "phase3ar2_deterministic_tests": True,
        "thinwallet_experiment": True,
        "pbmo": mode["pbmo"],
        "pbmo_transport": "tcp" if mode["pbmo"] else None,
        "token_lifecycle": mode["token_lifecycle"],
        "complete_memory_architecture": mode["memory_architecture"],
        "memory_flags": list(MEMORY_FLAGS) if mode["memory_architecture"] else [],
        "phase_metrics": profile != "off",
        "memory_sampler": profile != "off",
        "io_sampler": profile != "off",
        "network_metrics": profile != "off",
        "transcript_observer": profile == "audit",
        "commitment_observer": profile == "audit",
    }
    return env, enabled


def empty_raw_files(run_dir: Path) -> None:
    for name in ("phases.jsonl", "transcript_audit.jsonl", "commitments_audit.jsonl"):
        (run_dir / name).write_text("", encoding="utf-8")


def transport_metrics(backend: dict[str, Any] | None) -> dict[str, Any] | None:
    if not backend:
        return None
    report = backend.get("full_commitment_report")
    if not report:
        return None
    return report.get("metrics", {}).get("transport_metrics")


def network_record(mode_name: str, backend: dict[str, Any] | None) -> dict[str, Any]:
    tm = transport_metrics(backend)
    if not MODES[mode_name]["pbmo"]:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "measured",
            "connection_count": 0,
            "request_frame_count": 0,
            "response_frame_count": 0,
            "upload_bytes": 0,
            "download_bytes": 0,
            "request_breakdown": {
                "header_bytes": 0,
                "scalar_bytes": 0,
                "authentication_bytes": 0,
            },
            "response_breakdown": {
                "point_bytes": 0,
                "metadata_bytes": 0,
                "authentication_bytes": 0,
            },
            "timing_ns": {
                "connect": 0,
                "upload": 0,
                "server_wait": 0,
                "download": 0,
                "response_decode": 0,
            },
        }
    if tm is None:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "unavailable",
            "reason": "PBMO transport did not produce metrics",
            "upload_bytes": None,
            "download_bytes": None,
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "measured",
        "connection_count": tm.get("connection_count"),
        "request_frame_count": tm.get("request_frame_count"),
        "response_frame_count": tm.get("response_frame_count"),
        "upload_bytes": tm.get("request_bytes"),
        "download_bytes": tm.get("response_bytes"),
        "request_breakdown": {
            "header_bytes": tm.get("request_header_bytes"),
            "scalar_bytes": tm.get("request_scalar_bytes"),
            "authentication_bytes": tm.get("request_authentication_bytes"),
        },
        "response_breakdown": {
            "point_bytes": tm.get("response_point_bytes"),
            "metadata_bytes": tm.get("response_metadata_bytes"),
            "authentication_bytes": tm.get("response_authentication_bytes"),
        },
        "timing_ns": {
            "connect": tm.get("connect_ns"),
            "upload": tm.get("upload_ns"),
            "server_wait": tm.get("server_wait_ns"),
            "download": tm.get("download_ns"),
            "response_decode": tm.get("response_decode_ns"),
        },
    }


def phase_pairs_valid(path: Path) -> tuple[bool, str | None]:
    if not path.is_file():
        return False, "phases.jsonl missing"
    stack: list[str] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            if event["event"] == "begin":
                stack.append(event["phase"])
            elif event["event"] == "end":
                if event["phase"] not in stack:
                    return False, f"unpaired end for {event['phase']}"
                reverse_index = stack[::-1].index(event["phase"])
                del stack[len(stack) - reverse_index - 1]
    except (OSError, ValueError, KeyError) as error:
        return False, str(error)
    return (not stack, None if not stack else f"unpaired begins: {stack}")


def assert_mode(
    mode_name: str, backend: dict[str, Any] | None, network: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    if backend is None:
        return ["backend_result_missing"]
    counters = backend.get("execution_counters", {})
    missing = [name for name in COUNTER_NAMES if name not in counters]
    if missing:
        failures.append(f"missing_counters:{','.join(missing)}")
    pbmo = MODES[mode_name]["pbmo"]
    memory = MODES[mode_name]["memory_architecture"]
    upload = network.get("upload_bytes")
    download = network.get("download_bytes")
    if pbmo:
        for name in (
            "pbmo_sessions_started",
            "pbmo_sessions_completed",
            "pbmo_rows_uploaded",
            "pbmo_server_outputs_received",
            "aggregate_checks_executed",
            "aggregate_checks_passed",
        ):
            if counters.get(name, 0) <= 0:
                failures.append(f"{name}_not_positive")
        if counters.get("native_commitment_calls", 0) != 0:
            failures.append("native_commitment_calls_nonzero_in_pbmo_mode")
        if not isinstance(upload, int) or upload <= 0:
            failures.append("pbmo_upload_not_positive")
        if not isinstance(download, int) or download <= 0:
            failures.append("pbmo_download_not_positive")
    else:
        if counters.get("native_commitment_calls", 0) <= 0:
            failures.append("native_commitment_calls_not_positive")
        for name in (
            "pbmo_sessions_started",
            "pbmo_sessions_completed",
            "pbmo_rows_uploaded",
            "pbmo_server_outputs_received",
            "aggregate_checks_executed",
            "aggregate_checks_passed",
        ):
            if counters.get(name, 0) != 0:
                failures.append(f"{name}_nonzero_in_native_mode")
        if upload != 0 or download != 0:
            failures.append("network_bytes_nonzero_in_native_mode")
    folds = counters.get("external_fold_rounds", 0)
    if memory and folds <= 0:
        failures.append("external_fold_rounds_not_positive")
    if not memory and folds != 0:
        failures.append("external_fold_rounds_nonzero_without_memory_mode")
    if not backend.get("patched_verifier_accepts"):
        failures.append("native_verifier_rejected")
    return failures


def run_experiment(args: argparse.Namespace, quiet: bool = False) -> int:
    root = Path(args.repo_root).resolve()
    binary = Path(args.binary).resolve()
    if not binary.is_file():
        raise SystemExit(f"experiment binary does not exist: {binary}")
    if args.workload_seed != FIXED_WORKLOAD_SEED:
        raise SystemExit(
            f"current deterministic fixture supports only workload seed {FIXED_WORKLOAD_SEED}"
        )
    description = workload_description(binary, args.workload, root)
    metadata = description["metadata"]
    workload = description["canonical_name"]
    log_size = int(description["log_size"])
    device_id = args.device_id or socket.gethostname()
    run_dir = (
        Path(args.result_root).resolve()
        / device_id
        / workload
        / args.experiment_mode
        / args.run_id
    )
    if run_dir.exists():
        raise SystemExit(f"result directory already exists: {run_dir}")
    run_dir.mkdir(parents=True)
    empty_raw_files(run_dir)

    if args.experiment_temp_dir:
        temp_dir = Path(args.experiment_temp_dir).resolve()
        temp_dir.mkdir(parents=True, exist_ok=False)
        remove_temp = False
    else:
        # Keep file-backed prover state on the WSL-native filesystem. DrvFS
        # does not provide the Linux page-cache behavior assumed by
        # sync_data + posix_fadvise(DONTNEED) + immediate reread.
        temp_dir = Path(tempfile.mkdtemp(prefix="thinwallet-"))
        remove_temp = True
    fs_info = filesystem_info(temp_dir)
    profile = selected_profile(args)
    if profile == "perf" and fs_info["temp_root_is_drvfs"] and not getattr(
        args, "allow_unsafe_drvfs", False
    ):
        if remove_temp:
            shutil.rmtree(temp_dir, ignore_errors=True)
        raise SystemExit(
            "perf profile requires a WSL-native temp root; use "
            "--allow-unsafe-drvfs only for explicitly non-paper runs"
        )

    env, enabled = configure_environment(args, run_dir, temp_dir, workload)
    mode = MODES[args.experiment_mode]
    backend_command = [str(binary), str(mode["backend_command"]), str(log_size)]
    git_commit, git_dirty = git_metadata(root)
    source_hash, source_files = source_tree_hash(root)
    cargo_lock = root / "experiments" / "libspartan" / "Cargo.lock"
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source_provenance_type": "source-tree-hash",
        "source_tree_sha256": source_hash,
        "source_tree_file_count": len(source_files),
        "source_tree_inclusion_manifest": source_files,
        "cargo_lock_sha256": sha256_file(cargo_lock),
        "binary_sha256": sha256_file(binary),
        "pbmo_server_binary_sha256": sha256_file(Path(args.server_binary).resolve())
        if mode["pbmo"] and Path(args.server_binary).is_file()
        else None,
        "git_commit": git_commit,
        "git_dirty": git_dirty,
        "build_profile": "release",
        "enabled_features": enabled,
        "effective_configuration": effective_configuration(args.experiment_mode, args),
        "experiment_mode": args.experiment_mode,
        "mode_implementation": mode["implementation"],
        "workload": workload,
        "constraint_count": metadata["raw_constraints"],
        "padded_size": metadata["padded_size"],
        "witness_size": metadata["witness_elements"],
        "q": metadata["q"],
        "m": metadata["m"],
        "prover_seed_commitment": seed_commitment(
            "thinwallet/prover-seed/v1", args.prover_seed
        ),
        "pbmo_randomness_domain": "separate deterministic PBMO token/mask domains",
        "token_randomness_domain": "separate deterministic token generation/store domains",
        "prover_seed": args.prover_seed,
        "workload_seed": args.workload_seed,
        "thread_count": args.thread_count,
        "device_id": device_id,
        "device_model": None,
        "soc": cpu_model(),
        "total_ram_bytes": mem_total_bytes(),
        "android_version": None,
        "kernel_version": platform.release(),
        "charging_state": None,
        "battery_level_start": None,
        "ambient_temperature_if_available": None,
        "start_time_utc": datetime.now(timezone.utc).isoformat(),
        "temporary_storage_filesystem_policy": (
            "unique WSL-native temporary root; raw results remain in the repository"
        ),
        "instrumentation_profile": profile,
        "pss_sample_interval_ms": args.metrics_sample_ms if profile != "off" else None,
        **fs_info,
        "filesystem_valid_for_paper": not fs_info["temp_root_is_drvfs"],
        "command_line": sys.argv,
        "backend_command_line": backend_command,
        "capabilities": {
            "git_metadata": git_commit is not None,
            "source_tree_hash": True,
            "phase_events": profile != "off",
            "memory_timeline": profile != "off",
            "io_timeline": profile != "off",
            "network_accounting": profile != "off",
            "proof_equivalence": profile == "audit",
        },
        "unavailable": [
            "git metadata because the workspace is not a Git checkout"
            if git_commit is None
            else None,
            "Android-only battery, charging, and ambient temperature fields",
        ],
    }
    manifest["unavailable"] = [value for value in manifest["unavailable"] if value]
    json_write(run_dir / "manifest.json", manifest)

    child_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    wall_started = time.monotonic_ns()
    time_report_path = run_dir / "time-v.txt"
    executed_command = [
        "/usr/bin/time",
        "-v",
        "-o",
        str(time_report_path),
        *backend_command,
    ]
    try:
        completed = subprocess.run(
            executed_command,
            cwd=root / "experiments" / "libspartan",
            env=env,
            capture_output=True,
            text=True,
            timeout=getattr(args, "timeout_s", None),
        )
    except subprocess.TimeoutExpired as error:
        timeout_stdout = error.stdout or ""
        timeout_stderr = error.stderr or ""
        if isinstance(timeout_stdout, bytes):
            timeout_stdout = timeout_stdout.decode("utf-8", errors="replace")
        if isinstance(timeout_stderr, bytes):
            timeout_stderr = timeout_stderr.decode("utf-8", errors="replace")
        completed = subprocess.CompletedProcess(
            executed_command,
            124,
            stdout=timeout_stdout,
            stderr=timeout_stderr + "\nTHINWALLET_TIMEOUT\n",
        )
    wall_ns = time.monotonic_ns() - wall_started
    child_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    process_cpu_ns = int(
        (
            child_after.ru_utime
            + child_after.ru_stime
            - child_before.ru_utime
            - child_before.ru_stime
        )
        * 1_000_000_000
    )
    (run_dir / "stdout.log").write_text(completed.stdout, encoding="utf-8")
    (run_dir / "stderr.log").write_text(completed.stderr, encoding="utf-8")
    time_report = {}
    if time_report_path.is_file():
        for line in time_report_path.read_text(encoding="utf-8").splitlines():
            if ":" in line:
                key, value = line.strip().split(":", 1)
                time_report[key] = value.strip()

    backend_path = run_dir / "backend_result.json"
    backend = json_read(backend_path) if backend_path.is_file() else None
    network = network_record(args.experiment_mode, backend)
    json_write(run_dir / "network.json", network)
    pair_valid, pair_error = phase_pairs_valid(run_dir / "phases.jsonl")
    mode_failures = (
        assert_mode(args.experiment_mode, backend, network)
        if completed.returncode == 0 and profile != "off"
        else []
    )
    if profile != "off" and not pair_valid:
        mode_failures.append(f"phase_pairing:{pair_error}")
    success = completed.returncode == 0 and backend is not None and not mode_failures

    audit = {} if backend is None else backend.get("audit_digests", {})
    proof = {
        "schema_version": SCHEMA_VERSION,
        "proof_length": None if backend is None else backend["proof_size_bytes"],
        "proof_sha256": None if backend is None else backend["proof_sha256"],
        "proof_bytes_equal_to_native": None,
        "transcript_event_count": audit.get("transcript_event_count"),
        "transcript_sha256": audit.get("transcript_audit_sha256"),
        "transcript_equal_to_native": None,
        "logical_commitment_call_count": audit.get("logical_commitment_call_count"),
        "ordered_commitment_count": audit.get("ordered_commitment_count"),
        "ordered_commitments_sha256": audit.get("ordered_commitments_sha256"),
        "ordered_commitments_equal_to_native": None,
        "verifier_result": None if backend is None else backend["patched_verifier_accepts"],
        "verifier_is_unmodified": None
        if backend is None
        else not backend["verifier_source_modified"],
        "verifier_binary_or_code_hash": sha256_file(binary),
        "transcript_digest_semantics": (
            "rolling ordered event-stream digest; Merlin internal sponge state is unavailable"
        ),
    }
    json_write(run_dir / "proof.json", proof)
    json_write(
        run_dir / "token.json",
        {
            "schema_version": SCHEMA_VERSION,
            "enabled": mode["token_lifecycle"],
            "state": None if backend is None else backend["durable_token_state"],
            "token_file_bytes": None if backend is None else backend["token_size_bytes"],
            "token_id": None,
            "token_id_policy": "never log full token identifiers",
        },
    )

    temp_report_path = run_dir / "temp_storage.json"
    temp_report = (
        json_read(temp_report_path)
        if temp_report_path.is_file()
        else {
            "schema_version": SCHEMA_VERSION,
            "status": "unavailable",
            "reason": "in-process temporary-storage report was not emitted",
        }
    )
    cleanup_ok = None
    if remove_temp:
        try:
            shutil.rmtree(temp_dir)
            cleanup_ok = True
        except OSError:
            cleanup_ok = False
    temp_report["cleanup_success"] = cleanup_ok
    temp_report["post_cleanup_final_bytes"] = (
        0 if cleanup_ok else (sum(p.stat().st_size for p in temp_dir.rglob("*") if p.is_file())
                              if temp_dir.exists() else 0)
    )
    json_write(temp_report_path, temp_report)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "success" if success else "failed",
        "exit_status": completed.returncode,
        "experiment_mode": args.experiment_mode,
        "workload": workload,
        "run_id": args.run_id,
        "backend_result": backend,
        "instrumentation_status": "enabled" if profile != "off" else "disabled",
        "instrumentation_profile": profile,
        "mode_assertion_failures": mode_failures,
        "phase_pairs_valid": pair_valid if profile != "off" else None,
        "wall_ns": wall_ns,
        "process_cpu_ns": process_cpu_ns,
        "external_time_v": {
            "maximum_resident_set_size_kib": int(
                time_report["Maximum resident set size (kbytes)"]
            )
            if time_report.get("Maximum resident set size (kbytes)", "").isdigit()
            else None,
            "exit_status": completed.returncode,
        },
        "temporary_directory": {
            "path": str(temp_dir),
            "automatically_removed": remove_temp,
            "cleanup_succeeded": cleanup_ok,
        },
    }
    json_write(run_dir / "summary.json", summary)
    output = {
        "status": summary["status"],
        "result_directory": str(run_dir),
        "mode": args.experiment_mode,
        "workload": workload,
        "exit_status": completed.returncode,
        "mode_assertion_failures": mode_failures,
    }
    if not quiet:
        print(json.dumps(output, sort_keys=True))
    return 0 if success else completed.returncode or 1


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@contextmanager
def pbmo_server(
    root: Path, server_binary: Path, result_dir: Path, max_connections: int
) -> Iterator[tuple[str, Path]]:
    result_dir.mkdir(parents=True, exist_ok=True)
    key_path = result_dir / "pbmo-test-key.bin"
    key_path.write_bytes(hashlib.sha256(b"thinwallet/phase2/controlled-test-key").digest())
    port = free_port()
    endpoint = f"127.0.0.1:{port}"
    env = os.environ.copy()
    env.update(
        {
            "THINWALLET_PBMO_LISTEN": endpoint,
            "THINWALLET_PBMO_PSK_FILE": str(key_path),
            "THINWALLET_PBMO_SERVER_METRICS": str(result_dir / "server_connections.jsonl"),
            "THINWALLET_PBMO_MAX_CONNECTIONS": str(max_connections),
        }
    )
    stdout = (result_dir / "server.stdout.log").open("w", encoding="utf-8")
    stderr = (result_dir / "server.stderr.log").open("w", encoding="utf-8")
    process = subprocess.Popen(
        [str(server_binary)],
        cwd=root / "experiments" / "libspartan",
        env=env,
        stdout=stdout,
        stderr=stderr,
        text=True,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                # The readiness probe consumes a server connection, so servers are
                # provisioned with one extra connection by the caller.
                break
        time.sleep(0.05)
    if process.poll() is not None:
        stdout.close()
        stderr.close()
        raise RuntimeError("PBMO server failed to start")
    try:
        yield endpoint, key_path
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        stdout.close()
        stderr.close()
        key_path.unlink(missing_ok=True)


def child_args(
    args: argparse.Namespace,
    mode: str,
    run_id: str,
    seed: int,
    endpoint: str | None,
    psk: Path | None,
    instrumentation: bool,
) -> argparse.Namespace:
    return argparse.Namespace(
        experiment_mode=mode,
        workload=args.workload,
        run_id=run_id,
        device_id=args.device_id,
        prover_seed=seed,
        workload_seed=FIXED_WORKLOAD_SEED,
        thread_count=args.thread_count,
        memory_budget_mib=args.memory_budget_mib,
        pbmo_endpoint=endpoint,
        pbmo_psk_file=None if psk is None else str(psk),
        experiment_temp_dir=None,
        repo_root=args.repo_root,
        binary=args.binary,
        result_root=args.result_root,
        instrumentation=instrumentation,
        instrumentation_profile="audit" if instrumentation else "off",
        allow_unsafe_drvfs=False,
        timeout_s=getattr(args, "timeout_s", None),
        metrics_sample_ms=args.metrics_sample_ms,
    )


def run_path(args: argparse.Namespace, mode: str, run_id: str) -> Path:
    description = workload_description(
        Path(args.binary).resolve(), args.workload, Path(args.repo_root).resolve()
    )
    return (
        Path(args.result_root).resolve()
        / (args.device_id or socket.gethostname())
        / description["canonical_name"]
        / mode
        / run_id
    )


def apply_native_comparison(paths: dict[str, Path]) -> dict[str, Any]:
    native = json_read(paths["native"] / "proof.json")
    fields = ("proof_length", "proof_sha256", "transcript_event_count", "transcript_sha256",
              "ordered_commitment_count", "ordered_commitments_sha256")
    comparisons: dict[str, Any] = {}
    for mode, path in paths.items():
        proof_path = path / "proof.json"
        proof = json_read(proof_path)
        proof["proof_bytes_equal_to_native"] = (
            proof["proof_length"] == native["proof_length"]
            and proof["proof_sha256"] == native["proof_sha256"]
        )
        proof["transcript_equal_to_native"] = (
            proof["transcript_event_count"] == native["transcript_event_count"]
            and proof["transcript_sha256"] == native["transcript_sha256"]
        )
        proof["ordered_commitments_equal_to_native"] = (
            proof["ordered_commitment_count"] == native["ordered_commitment_count"]
            and proof["ordered_commitments_sha256"] == native["ordered_commitments_sha256"]
        )
        json_write(proof_path, proof)
        comparisons[mode] = {field: proof.get(field) for field in fields}
        comparisons[mode].update(
            {
                "proof_equal": proof["proof_bytes_equal_to_native"],
                "transcript_equal": proof["transcript_equal_to_native"],
                "commitments_equal": proof["ordered_commitments_equal_to_native"],
                "verifier_accepts": proof["verifier_result"],
            }
        )
    return comparisons


def compare_modes(args: argparse.Namespace) -> int:
    root = Path(args.repo_root).resolve()
    server_binary = Path(args.server_binary).resolve()
    orchestration = Path(args.result_root).resolve() / "_phase2_orchestration" / args.batch_id
    order = list(MODES)
    random.Random(args.prover_seed).shuffle(order)
    paths: dict[str, Path] = {}
    with pbmo_server(root, server_binary, orchestration, 3) as (endpoint, psk):
        for index, mode in enumerate(order):
            run_id = f"{args.batch_id}-{index:02d}-{mode}"
            child = child_args(args, mode, run_id, args.prover_seed, endpoint, psk, True)
            if run_experiment(child, quiet=True) != 0:
                return 1
            paths[mode] = run_path(args, mode, run_id)
    comparisons = apply_native_comparison(paths)
    accepted = all(
        value["proof_equal"]
        and value["transcript_equal"]
        and value["commitments_equal"]
        and value["verifier_accepts"]
        for value in comparisons.values()
    )
    json_write(
        orchestration / "comparison.json",
        {
            "schema_version": SCHEMA_VERSION,
            "status": "success" if accepted else "failed",
            "seed": args.prover_seed,
            "execution_order": order,
            "run_directories": {mode: str(path) for mode, path in paths.items()},
            "comparisons": comparisons,
        },
    )
    print(json.dumps({"status": "success" if accepted else "failed",
                      "comparison": str(orchestration / "comparison.json")}, sort_keys=True))
    return 0 if accepted else 1


def mode_isolation(args: argparse.Namespace) -> int:
    root = Path(args.repo_root).resolve()
    output_dir = Path(args.result_root).resolve() / "_phase2_isolation"
    output_dir.mkdir(parents=True, exist_ok=True)
    down_port = free_port()
    down_endpoint = f"127.0.0.1:{down_port}"
    down_key = output_dir / "down-key.bin"
    down_key.write_bytes(hashlib.sha256(b"thinwallet/phase2/down-key").digest())
    records = []
    for index, mode in enumerate(MODES):
        run_id = f"isolation-down-{index:02d}-{mode}"
        child = child_args(
            args, mode, run_id, args.prover_seed, down_endpoint, down_key, True
        )
        status = run_experiment(child, quiet=True)
        expected = status != 0 if MODES[mode]["pbmo"] else status == 0
        records.append(
            {
                "server": "down",
                "mode": mode,
                "exit_status": status,
                "expected_result": "fail" if MODES[mode]["pbmo"] else "success",
                "matches_expectation": expected,
                "run_directory": str(run_path(args, mode, run_id)),
            }
        )
    down_key.unlink(missing_ok=True)

    with pbmo_server(
        root, Path(args.server_binary).resolve(), output_dir / "server-up", 3
    ) as (endpoint, psk):
        for index, mode in enumerate(MODES):
            run_id = f"isolation-up-{index:02d}-{mode}"
            child = child_args(args, mode, run_id, args.prover_seed, endpoint, psk, True)
            status = run_experiment(child, quiet=True)
            path = run_path(args, mode, run_id)
            network = json_read(path / "network.json")
            expected_bytes = (
                network.get("upload_bytes", 0) > 0
                if MODES[mode]["pbmo"]
                else network.get("upload_bytes") == 0
                and network.get("download_bytes") == 0
            )
            records.append(
                {
                    "server": "up",
                    "mode": mode,
                    "exit_status": status,
                    "expected_result": "success",
                    "network_matches_expectation": expected_bytes,
                    "matches_expectation": status == 0 and expected_bytes,
                    "run_directory": str(path),
                }
            )
    accepted = all(record["matches_expectation"] for record in records)
    target = Path(args.summary_root).resolve() / "mode_isolation.json"
    json_write(
        target,
        {
            "schema_version": SCHEMA_VERSION,
            "status": "success" if accepted else "failed",
            "records": records,
        },
    )
    print(json.dumps({"status": "success" if accepted else "failed",
                      "result": str(target)}, sort_keys=True))
    return 0 if accepted else 1


def instrumentation_overhead(args: argparse.Namespace) -> int:
    root = Path(args.repo_root).resolve()
    output_dir = Path(args.result_root).resolve() / "_phase2_overhead"
    records = []
    # One warm-up for each instrumentation state, followed by five measured runs.
    with pbmo_server(
        root, Path(args.server_binary).resolve(), output_dir / "server", 13
    ) as (endpoint, psk):
        order = [(state, measured) for state in (False, True)
                 for measured in (False, True, True, True, True, True)]
        for index, (instrumentation, measured) in enumerate(order):
            label = "on" if instrumentation else "off"
            run_id = f"overhead-{index:02d}-{label}-{'measured' if measured else 'warmup'}"
            child = child_args(
                args, "full", run_id, args.prover_seed, endpoint, psk, instrumentation
            )
            status = run_experiment(child, quiet=True)
            path = run_path(args, "full", run_id)
            summary = json_read(path / "summary.json")
            proof = json_read(path / "proof.json")
            records.append(
                {
                    "instrumentation": label,
                    "measured": measured,
                    "exit_status": status,
                    "wall_ns": summary["wall_ns"],
                    "process_cpu_ns": summary["process_cpu_ns"],
                    "proof_length": proof["proof_length"],
                    "proof_sha256": proof["proof_sha256"],
                    "verifier_result": proof["verifier_result"],
                    "run_directory": str(path),
                }
            )
    measured = [record for record in records if record["measured"]]
    medians = {}
    for label in ("off", "on"):
        group = [record for record in measured if record["instrumentation"] == label]
        medians[label] = {
            "wall_ns": statistics.median(record["wall_ns"] for record in group),
            "process_cpu_ns": statistics.median(record["process_cpu_ns"] for record in group),
        }
    baseline = measured[0]
    equivalent = all(
        record["proof_length"] == baseline["proof_length"]
        and record["proof_sha256"] == baseline["proof_sha256"]
        and record["verifier_result"]
        and record["exit_status"] == 0
        for record in measured
    )
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "success" if equivalent else "failed",
        "mode": "full",
        "same_seed": args.prover_seed,
        "same_thread_count": args.thread_count,
        "records": records,
        "median": medians,
        "relative_overhead": {
            "wall": medians["on"]["wall_ns"] / medians["off"]["wall_ns"] - 1,
            "process_cpu": (
                medians["on"]["process_cpu_ns"]
                / medians["off"]["process_cpu_ns"]
                - 1
            ),
        },
        "result_equivalence": equivalent,
    }
    target = Path(args.summary_root).resolve() / "instrumentation_overhead.json"
    json_write(target, result)
    print(json.dumps({"status": result["status"], "result": str(target)}, sort_keys=True))
    return 0 if equivalent else 1


def phase2_matrix(args: argparse.Namespace) -> int:
    root = Path(args.repo_root).resolve()
    output_dir = Path(args.result_root).resolve() / "_phase2_matrix" / args.batch_id
    order_rng = random.Random(0x504841534532)
    measured_order = [(seed, mode) for seed in PHASE2_SEEDS for mode in MODES]
    order_rng.shuffle(measured_order)
    warmup_order = list(MODES)
    order_rng.shuffle(warmup_order)
    all_runs = [(None, mode, False) for mode in warmup_order] + [
        (seed, mode, True) for seed, mode in measured_order
    ]
    paths_by_seed: dict[int, dict[str, Path]] = {seed: {} for seed in PHASE2_SEEDS}
    records = []
    pbmo_connections = sum(1 for _, mode, _ in all_runs if MODES[mode]["pbmo"])
    with pbmo_server(
        root,
        Path(args.server_binary).resolve(),
        output_dir / "server",
        pbmo_connections + 1,
    ) as (endpoint, psk):
        for index, (seed, mode, measured) in enumerate(all_runs):
            actual_seed = PHASE2_SEEDS[0] if seed is None else seed
            run_id = (
                f"{args.batch_id}-{index:02d}-"
                f"{'measured' if measured else 'warmup'}-{mode}-seed{actual_seed}"
            )
            child = child_args(
                args, mode, run_id, actual_seed, endpoint, psk, True
            )
            status = run_experiment(child, quiet=True)
            path = run_path(args, mode, run_id)
            records.append(
                {
                    "order": index,
                    "measured": measured,
                    "seed": actual_seed,
                    "mode": mode,
                    "exit_status": status,
                    "run_directory": str(path),
                }
            )
            if status != 0:
                json_write(output_dir / "matrix.json", {"status": "failed", "runs": records})
                return 1
            if measured:
                paths_by_seed[actual_seed][mode] = path
    comparisons = {}
    accepted = True
    for seed, paths in paths_by_seed.items():
        comparison = apply_native_comparison(paths)
        comparisons[str(seed)] = comparison
        accepted &= all(
            item["proof_equal"]
            and item["transcript_equal"]
            and item["commitments_equal"]
            and item["verifier_accepts"]
            for item in comparison.values()
        )
    json_write(
        output_dir / "matrix.json",
        {
            "schema_version": SCHEMA_VERSION,
            "status": "success" if accepted else "failed",
            "workload": args.workload,
            "warmup_count": 4,
            "measured_count": 20,
            "public_seeds": list(PHASE2_SEEDS),
            "randomized_execution_order": records,
            "comparisons": comparisons,
        },
    )
    print(json.dumps({"status": "success" if accepted else "failed",
                      "result": str(output_dir / "matrix.json")}, sort_keys=True))
    return 0 if accepted else 1


def add_common_arguments(command: argparse.ArgumentParser, root: Path) -> None:
    command.add_argument("--workload", default="S-W1")
    command.add_argument("--device-id", default="local-wsl-phase2")
    command.add_argument("--prover-seed", type=int, default=DEFAULT_PROVER_SEED)
    command.add_argument("--thread-count", type=int, default=1)
    command.add_argument("--memory-budget-mib", type=int, default=2048)
    command.add_argument("--timeout-s", type=float, default=None)
    command.add_argument("--metrics-sample-ms", type=int, default=250)
    command.add_argument("--repo-root", default=str(root))
    command.add_argument(
        "--binary",
        default=str(
            root / "experiments" / "libspartan" / "target" / "release"
            / "thinwallet_android_bench"
        ),
    )
    command.add_argument(
        "--server-binary",
        default=str(
            root / "experiments" / "libspartan" / "target" / "release"
            / "pbmo_tcp_server"
        ),
    )
    command.add_argument("--result-root", default=str(root / "results" / "raw"))
    command.add_argument("--summary-root", default=str(root / "results" / "summary"))


def parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    result = argparse.ArgumentParser(prog="thinwallet-bench")
    commands = result.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    add_common_arguments(run, root)
    run.add_argument("--experiment-mode", choices=sorted(MODES), required=True)
    run.add_argument("--run-id", required=True)
    run.add_argument("--workload-seed", type=int, default=FIXED_WORKLOAD_SEED)
    run.add_argument("--pbmo-endpoint")
    run.add_argument("--pbmo-psk-file")
    run.add_argument("--experiment-temp-dir")
    run.add_argument("--instrumentation", action=argparse.BooleanOptionalAction, default=True)
    run.add_argument(
        "--instrumentation-profile",
        choices=("off", "perf", "audit"),
        default=None,
    )
    run.add_argument("--allow-unsafe-drvfs", action="store_true")
    run.set_defaults(handler=run_experiment)

    compare = commands.add_parser("compare-modes")
    add_common_arguments(compare, root)
    compare.add_argument("--batch-id", required=True)
    compare.set_defaults(handler=compare_modes)

    isolation = commands.add_parser("mode-isolation")
    add_common_arguments(isolation, root)
    isolation.set_defaults(handler=mode_isolation)

    overhead = commands.add_parser("instrumentation-overhead")
    add_common_arguments(overhead, root)
    overhead.set_defaults(handler=instrumentation_overhead)

    matrix = commands.add_parser("phase2-matrix")
    add_common_arguments(matrix, root)
    matrix.add_argument("--batch-id", required=True)
    matrix.set_defaults(handler=phase2_matrix)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.thread_count < 1:
        raise SystemExit("--thread-count must be positive")
    if args.memory_budget_mib < 1:
        raise SystemExit("--memory-budget-mib must be positive")
    if args.metrics_sample_ms < 1:
        raise SystemExit("--metrics-sample-ms must be positive")
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
