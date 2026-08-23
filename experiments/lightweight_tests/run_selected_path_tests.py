#!/usr/bin/env python3
"""Small host integration checks for Selected, ARE failures, and PBMO release."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "experiments/libspartan"
CLIENT = CRATE / "target/release/thinwallet_eval_client"
PBMO_CLIENT = CRATE / "target/release/phase_v2_pbmo"
SERVER = CRATE / "target/release/thinwallet_eval_server"
OUTPUT = ROOT / "results/selected_path_tests.txt"


def endpoint() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{listener.getsockname()[1]}"


def start_server(address: str, work: Path) -> tuple[subprocess.Popen[bytes], Any, Any]:
    output = work / "output"
    state = work / "state"
    output.mkdir(parents=True)
    state.mkdir(parents=True)
    stdout = (work / "stdout.log").open("wb")
    stderr = (work / "stderr.log").open("wb")
    env = dict(os.environ)
    env["THINWALLET_REMOTE_EVAL_SERVER_STATE_DIR"] = str(state)
    process = subprocess.Popen(
        [str(SERVER), address, str(output)],
        cwd=CRATE,
        env=env,
        stdout=stdout,
        stderr=stderr,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if (output / "startup.json").is_file():
            return process, stdout, stderr
        if process.poll() is not None:
            raise RuntimeError(f"ARE server exited during startup: {process.returncode}")
        time.sleep(0.05)
    raise RuntimeError("ARE server startup timeout")


def stop_server(process: subprocess.Popen[bytes], stdout: Any, stderr: Any) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    stdout.close()
    stderr.close()


def common_env(run: Path, seed: int) -> dict[str, str]:
    env = dict(os.environ)
    for key in list(env):
        if "PBMO" in key or key.startswith("THINWALLET_PREGENERATED_TOKEN"):
            env.pop(key, None)
    state = run / "state"
    temp = run / "temp"
    state.mkdir(parents=True)
    temp.mkdir(parents=True)
    env.update(
        {
            "THINWALLET_SPARTAN_RANDOMNESS_MODE": "split-independent",
            "THINWALLET_EXPERIMENT_PROVER_SEED": str(seed),
            "THINWALLET_EXPERIMENT_RUN_ID": run.name,
            "THINWALLET_PROOF_SESSION_ID": run.name,
            "THINWALLET_STATE_DIR": str(state),
            "THINWALLET_TEMP_DIR": str(temp),
            "THINWALLET_EXPERIMENT_TEMP_DIR": str(temp),
            "V3A_STATE_DIR": str(temp),
            "V3B_STATE_DIR": str(state),
            "THINWALLET_RESULT_OUT": str(run / "backend_result.json"),
            "THINWALLET_PROOF_OUT": str(run / "proof.bin"),
            "THINWALLET_COUNTERS_PATH": str(run / "execution_counters.json"),
            "THINWALLET_PHASES_PATH": str(run / "phases.jsonl"),
            "THINWALLET_PHASE_MARKER_PATH": str(run / "phase_markers.txt"),
            "THINWALLET_MEMORY_CSV_PATH": str(run / "memory.csv"),
            "THINWALLET_IO_CSV_PATH": str(run / "io.csv"),
            "THINWALLET_TEMP_ARTIFACTS_PATH": str(run / "temp_artifacts.json"),
            "THINWALLET_INSTRUMENTATION_PROFILE": "perf",
            "THINWALLET_DEFER_UPSTREAM_VERIFY": "0",
            "THINWALLET_MEMORY_BUDGET_MIB": "256",
            "LIBSPARTAN_TRANSCRIPT_RECOMPUTE": "1",
            "LIBSPARTAN_FIXED_STREAMING": "1",
            "LIBSPARTAN_MULTI_TARGET_STREAMING": "1",
            "LIBSPARTAN_ACTIVE_STATE_STREAMING": "1",
            "LIBSPARTAN_EPHEMERAL_STATE": "1",
            "LIBSPARTAN_CREDENTIAL_STREAMING": "0",
            "RAYON_NUM_THREADS": "1",
        }
    )
    return env


def run_client(
    run: Path,
    command: list[str],
    env: dict[str, str],
    timeout: int = 90,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=CRATE,
        env=env,
        stdout=(run / "stdout.log").open("wb"),
        stderr=(run / "stderr.log").open("wb"),
        timeout=timeout,
        check=False,
    )


def selected_success(work: Path, address: str) -> tuple[bool, list[str]]:
    run = work / "selected-success"
    run.mkdir()
    env = common_env(run, 1_609_001)
    env["THINWALLET_REMOTE_EVAL_ENDPOINT"] = address
    env["THINWALLET_REMOTE_EVAL_ALLOW_CACHE_PROVISION"] = "1"
    completed = run_client(run, [str(CLIENT), "native", "12"], env)
    backend = json.loads((run / "backend_result.json").read_text()) if completed.returncode == 0 else {}
    counters = backend.get("execution_counters", {})
    token_paths = list(run.rglob("*.pbmo")) + list(run.rglob("lifecycle.journal"))
    assertions = {
        "exit_status_zero": completed.returncode == 0,
        "low_residency_profile_enabled": env["LIBSPARTAN_MULTI_TARGET_STREAMING"] == "1",
        "local_row_msm_used": counters.get("native_row_msm_calls", 0) > 0,
        "are_used": counters.get("remote_eval_requests") == 1,
        "local_eval_not_used": counters.get("local_r1cs_eval_prove_calls", 0) == 0,
        "native_eval_verified": counters.get("native_eval_verify_pass") == 1,
        "native_full_verified": counters.get("native_full_verify_calls") == 1
        and backend.get("patched_verifier_accepts") is True
        and backend.get("original_upstream_verifier_accepts") is True,
        "proof_released": counters.get("remote_eval_final_proof_released") == 1
        and (run / "proof.bin").is_file(),
        "no_pbmo_token_or_store": not token_paths
        and backend.get("durable_token_state") is None
        and counters.get("pbmo_token_generation_calls", 0) == 0
        and counters.get("pregenerated_token_load_calls", 0) == 0,
    }
    return all(assertions.values()), [f"{key}={value}" for key, value in assertions.items()]


def selected_are_failures(work: Path, address: str, server_output: Path) -> tuple[bool, list[str]]:
    details: list[str] = []
    all_passed = True
    fault_file = server_output / "fault_mode.txt"
    for index, fault in enumerate(
        ("modified_eval_proof_byte", "other_invocation_response", "replayed_completed_invocation"),
        1,
    ):
        fault_file.write_text(fault, encoding="utf-8")
        run = work / f"selected-fault-{index}-{fault}"
        run.mkdir()
        env = common_env(run, 1_609_100 + index)
        env["THINWALLET_REMOTE_EVAL_ENDPOINT"] = address
        env["THINWALLET_REMOTE_EVAL_ALLOW_CACHE_PROVISION"] = "1"
        completed = run_client(run, [str(CLIENT), "native", "12"], env)
        stderr = (run / "stderr.log").read_text(encoding="utf-8", errors="replace")
        passed = (
            completed.returncode != 0
            and not (run / "proof.bin").exists()
            and "without local fallback" in stderr
        )
        all_passed &= passed
        details.append(
            f"fault={fault} rejected={completed.returncode != 0} "
            f"proof_released={(run / 'proof.bin').exists()} "
            f"no_local_fallback={'without local fallback' in stderr}"
        )
    fault_file.unlink(missing_ok=True)
    return all_passed, details


def pbmo_release_gate(work: Path) -> tuple[bool, list[str]]:
    run = work / "pbmo-release-gate"
    run.mkdir()
    env = common_env(run, 1_609_200)
    token_store = run / "token-store"
    env["THINWALLET_TOKEN_STORE_ROOT"] = str(token_store)
    completed = run_client(run, [str(PBMO_CLIENT), "malicious", "12"], env)
    backend = json.loads((run / "backend_result.json").read_text()) if completed.returncode == 0 else {}
    markers = []
    marker_path = run / "phase_markers.txt"
    if marker_path.is_file():
        for line in marker_path.read_text().splitlines():
            markers.append(line.split("\t", 1)[0])
    source = (CRATE / "src/bin/phase_v2_pbmo.rs").read_text(encoding="utf-8")
    patched_verify = source.index("let patched_accepts")
    original_verify = source.index("let original_accepts", patched_verify)
    spend = source.index("let state = attempt.mark_spent()", original_verify)
    release = source.index('fs::write(path, &bytes)', spend)
    ordering = patched_verify < original_verify < spend < release
    assertions = {
        "exit_status_zero": completed.returncode == 0,
        "patched_full_verify_pass": backend.get("patched_verifier_accepts") is True,
        "baseline_full_verify_pass": backend.get("original_upstream_verifier_accepts") is True,
        "durable_state_spent": backend.get("durable_token_state") == "SPENT",
        "spent_marker_observed": "AFTER_SPENT" in markers and "TOKEN_FINALIZED" in markers,
        "proof_released": (run / "proof.bin").is_file(),
        "source_order_verify_then_spent_then_release": ordering,
    }
    details = [f"{key}={value}" for key, value in assertions.items()]
    if completed.returncode != 0:
        stderr = (run / "stderr.log").read_text(encoding="utf-8", errors="replace")
        details.append("stderr_tail=" + " | ".join(stderr.splitlines()[-4:]))
    return all(assertions.values()), details


def main() -> int:
    results: list[tuple[str, bool, list[str], str]] = []
    with tempfile.TemporaryDirectory(prefix="thinwallet-selected-tests-") as temporary:
        work = Path(temporary)
        address = endpoint()
        process, stdout, stderr = start_server(address, work / "server")
        try:
            passed, details = selected_success(work, address)
            results.append(
                (
                    "selected_without_pbmo",
                    passed,
                    details,
                    "thinwallet_eval_client native 12 (separate ARE server)",
                )
            )
            passed, details = selected_are_failures(
                work, address, work / "server/output"
            )
            results.append(
                (
                    "selected_are_fail_closed",
                    passed,
                    details,
                    "thinwallet_eval_client native 12 x3 with server fault modes",
                )
            )
        finally:
            stop_server(process, stdout, stderr)
        passed, details = pbmo_release_gate(work)
        results.append(
            (
                "pbmo_release_after_verify_and_spent",
                passed,
                details,
                "phase_v2_pbmo malicious 12 (loopback PBMO)",
            )
        )

    lines = [
        "ThinWallet Selected-path lightweight host integration tests",
        "Build: cargo build --offline --locked --release --bin thinwallet_eval_client --bin thinwallet_eval_server --bin phase_v2_pbmo",
        "Scope: log_size=12 synthetic relation; no phone, network, or formal campaign",
        "",
    ]
    for name, passed, details, command in results:
        lines.append(f"TEST {name}: {'PASS' if passed else 'FAIL'}")
        lines.append(f"command: {command}")
        lines.extend(f"assert: {detail}" for detail in details)
        lines.append("")
    lines.append(f"SUMMARY: passed={sum(result[1] for result in results)}/{len(results)}")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(lines[-1])
    return 0 if all(result[1] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
