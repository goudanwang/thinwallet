#!/usr/bin/env python3
"""Run the vendored-baseline verifier executable over saved headline proofs."""

from __future__ import annotations

import csv
import hashlib
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BINARY = (
    ROOT
    / "experiments/lightweight_tests/standalone_verifier/target/release/"
    "thinwallet-standalone-verifier"
)
RUN_ROOT = ROOT / "experiments/android_phase5f_c/results/runs"
OUTPUT = ROOT / "results/standalone_verifier.csv"
BASELINE = ROOT / "experiments/libspartan/vendor/spartan-baseline-testable-0.9.0"

FIELDS = [
    "run_id",
    "workload",
    "mode",
    "proof_sha256",
    "public_input_sha256",
    "verifier_source_id",
    "verifier_binary_sha256",
    "verify_result",
    "error",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(path for path in root.rglob("*") if path.is_file()):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(sha256(path)))
    return digest.hexdigest()


def cases() -> list[dict[str, str | Path]]:
    rows: list[dict[str, str | Path]] = []
    modes = {"M1": "Memory-local", "M2": "Selected", "M4": "PBMO-enabled"}
    for workload, source_name, source_file in (
        (
            "H1",
            "S-WK-k52-r1-d32-sparse-merkle",
            "S_WK_k52_r1_d32_sparse_merkle.twcs",
        ),
        (
            "H2",
            "S-WK-k8-r8-d32-sparse-merkle",
            "S_WK_k8_r8_d32_sparse_merkle.twcs",
        ),
    ):
        for mode_code, mode in modes.items():
            for repetition in range(1, 6):
                run_id = f"phase5fc_formal_{workload}_{mode_code}_r{repetition}"
                rows.append(
                    {
                        "run_id": run_id,
                        "workload": workload,
                        "source_name": source_name,
                        "source": ROOT
                        / "experiments/credential_workloads/results/v4e/sources"
                        / source_file,
                        "mode": mode,
                        "proof": RUN_ROOT / run_id / "proof.bin",
                    }
                )
    return rows


def main() -> int:
    binary_hash = sha256(BINARY)
    source_id = f"spartan-baseline-testable-0.9.0-tree-sha256:{tree_sha256(BASELINE)}"
    rows = cases()
    result_by_run: dict[str, tuple[str, str, str, str]] = {}
    for source_name in sorted({str(row["source_name"]) for row in rows}):
        group = [row for row in rows if row["source_name"] == source_name]
        found = [row for row in group if Path(row["proof"]).is_file()]
        if not found:
            continue
        command = [
            str(BINARY),
            source_name,
            str(found[0]["source"]),
            *(str(row["proof"]) for row in found),
        ]
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=600,
            check=False,
        )
        if completed.returncode != 0:
            error = completed.stderr.strip().replace("\n", " ")
            for row in found:
                result_by_run[str(row["run_id"])] = (
                    sha256(Path(row["proof"])),
                    "MISSING",
                    "ERROR",
                    error,
                )
            continue
        for line in completed.stdout.splitlines():
            parts = line.split("\t", 4)
            if len(parts) != 5:
                continue
            run_id, proof_hash, public_hash, result, error = parts
            result_by_run[run_id] = (proof_hash, public_hash, result, error)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            run_id = str(row["run_id"])
            proof = Path(row["proof"])
            if not proof.is_file():
                values = ("MISSING", "MISSING", "MISSING", "proof bytes not found")
            else:
                values = result_by_run.get(
                    run_id,
                    (sha256(proof), "MISSING", "ERROR", "verifier emitted no record"),
                )
            proof_hash, public_hash, result, error = values
            writer.writerow(
                {
                    "run_id": run_id,
                    "workload": row["workload"],
                    "mode": row["mode"],
                    "proof_sha256": proof_hash,
                    "public_input_sha256": public_hash,
                    "verifier_source_id": source_id,
                    "verifier_binary_sha256": binary_hash,
                    "verify_result": result,
                    "error": error,
                }
            )
    passed = sum(result[2] == "PASS" for result in result_by_run.values())
    print(f"wrote {OUTPUT.relative_to(ROOT)}: passed={passed}, rows={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
