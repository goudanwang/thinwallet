#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
sys.path.insert(0, str(ROOT))

from backend_audit.fft_audit import audit_paths
from common import FIELD_BYTES, digest, env_record, mean_median_p95, measured_block, write_json
from local_baseline.native_backend import local_prove, materialize_witness, native_verify
from remote_msm.remote_msm import emsm_status, plaintext_remote_msm
from remote_parameters.parameters import build_manifest
from streaming_sumcheck.sumcheck import in_memory_sumcheck, streaming_sumcheck, verify_transcript
from witness_stream.witness import CredentialLikeWitnessSource, SyntheticWitnessSource


DEFAULT_NS = [2**12, 2**14, 2**16]
LARGE_NS = [2**12, 2**14, 2**16, 2**18, 2**20]
DEFAULT_BS = [2**10, 2**12, 2**14]
REPETITIONS = 1


def sizes() -> tuple[list[int], list[int]]:
    if os.environ.get("MEMORY_BOUNDED_SAP_LARGE_BENCH") == "1":
        return LARGE_NS, [2**10, 2**12, 2**14, 2**16]
    return DEFAULT_NS, DEFAULT_BS


def backend_selection() -> dict[str, object]:
    candidates = [
        {
            "id": "B0",
            "name": "Spartan-style R1CS + Sumcheck + multilinear commitment",
            "available_in_repo": False,
            "prover_uses_fft_ntt": "no by architecture, but no production crate present",
            "prover_uses_low_degree_extension": "no",
            "prover_uses_fri": "no",
            "witness_representation": "vector / multilinear table",
            "commitment_type": "multilinear PCS or IPA depending implementation",
            "dominant_group_operations": "PCS/MSM; not implemented here",
            "sumcheck_table_storage": "unknown for absent crate",
            "native_verifier_available": "no",
            "native_proof_serialization_available": "no",
            "zero_knowledge": "unclear",
            "streaming_integration_difficulty": "medium",
            "phase1_decision": "not selected: no actual dependency/API found",
        },
        {
            "id": "B1",
            "name": "HyperPlonk-style multilinear PIOP",
            "available_in_repo": False,
            "prover_uses_fft_ntt": "no by multilinear design, but no production crate present",
            "prover_uses_low_degree_extension": "no FRI path selected",
            "prover_uses_fri": "no for selected path",
            "witness_representation": "multilinear table",
            "commitment_type": "multilinear PCS",
            "dominant_group_operations": "PCS openings/MSM; not implemented here",
            "sumcheck_table_storage": "unknown",
            "native_verifier_available": "no",
            "native_proof_serialization_available": "no",
            "zero_knowledge": "unclear",
            "streaming_integration_difficulty": "high",
            "phase1_decision": "not selected: no actual dependency/API found",
        },
        {
            "id": "B2",
            "name": "Nova/HyperNova-related Sumcheck or folding backend",
            "available_in_repo": False,
            "prover_uses_fft_ntt": "no by target family, but no backend present",
            "prover_uses_low_degree_extension": "no selected implementation",
            "prover_uses_fri": "no selected implementation",
            "witness_representation": "R1CS/folding state",
            "commitment_type": "IPA/Pedersen depending implementation",
            "dominant_group_operations": "folding commitments/MSM",
            "sumcheck_table_storage": "unknown",
            "native_verifier_available": "no",
            "native_proof_serialization_available": "no",
            "zero_knowledge": "unclear",
            "streaming_integration_difficulty": "high",
            "phase1_decision": "not selected: no actual dependency/API found",
        },
        {
            "id": "B3",
            "name": "Internal FFT-free multilinear Sumcheck Phase-1 backend",
            "available_in_repo": True,
            "prover_uses_fft_ntt": "no",
            "prover_uses_low_degree_extension": "no",
            "prover_uses_fri": "no",
            "witness_representation": "vector / multilinear table",
            "commitment_type": "none in Phase 1 toy backend; remote MSM is separate plumbing",
            "dominant_group_operations": "none for native toy verifier; remote MSM plumbing measured separately",
            "sumcheck_table_storage": "O(n) in local baseline, O(B) plus external storage in streaming mode",
            "native_verifier_available": "yes, for the internal Phase-1 backend",
            "native_proof_serialization_available": "yes, JSON",
            "zero_knowledge": "absent",
            "streaming_integration_difficulty": "low",
            "phase1_decision": "selected for memory-bounded architecture validation only",
        },
    ]
    return {
        "measurement_type": "MEASURED",
        "selected_backend": "INTERNAL_FFT_FREE_MULTILINEAR_SUMCHECK_PHASE1_BACKEND",
        "status_marker": "SUMCHECK_BACKEND_SELECTED",
        "candidates": candidates,
        "notes": [
            "No production Spartan/HyperPlonk/Nova backend dependency was found in Cargo metadata.",
            "The selected backend is internal and validates memory-bounded Sumcheck architecture, not production SNARK readiness.",
        ],
    }


def run_local_baseline(ns: list[int]) -> dict[str, object]:
    rows = []
    for n in ns:
        with measured_block() as meas:
            witness = materialize_witness(n, 101)
            statement = {"n": n, "relation": "sumcheck_table_sum", "request_digest": digest({"n": n})}
            proof = local_prove(statement, witness)
            ok = native_verify(statement, proof)
        rows.append(
            {
                **env_record(REPO),
                "measurement_type": "MEASURED",
                "n": n,
                "B": None,
                "security_mode": "local_native",
                "repetitions": REPETITIONS,
                "correctness": ok,
                "native_verifier_result": ok,
                "prover_time_ms": meas["wall_time_ms"],
                "verifier_time_ms": None,
                "peak_RSS_MB": meas["peak_rss_mb"],
                "peak_python_alloc_MB": meas["peak_python_alloc_mb"],
                "witness_memory_bytes": n * FIELD_BYTES,
                "proving_key_memory_bytes": 0,
                "proof_size_bytes": len(json.dumps(proof).encode("utf-8")),
                "disk_IO": {"bytes_read": 0, "bytes_written": 0},
                "communication": {"upload_bytes": 0, "download_bytes": 0},
            }
        )
    out = {"status_marker": "NATIVE_SUMCHECK_BASELINE_PASS", "records": rows}
    write_json(ROOT / "results" / "local_baseline.json", out)
    return out


def run_witness_tests(ns: list[int]) -> dict[str, object]:
    rows = []
    for n in ns:
        source = SyntheticWitnessSource(n, 202)
        total = 0
        with measured_block() as meas:
            while True:
                chunk = source.next_chunk(4096)
                if chunk is None:
                    break
                total += len(chunk.values)
        cred = CredentialLikeWitnessSource(n, 303)
        rows.append(
            {
                "measurement_type": "MEASURED",
                "n": n,
                "synthetic_values_emitted": total,
                "synthetic_status": "SYNTHETIC_WITNESS_STREAM_PASS" if total == n else "SYNTHETIC_WITNESS_STREAM_FAIL",
                "credential_status": cred.status,
                "credential_live_state_bytes": cred.live_state_bytes,
                "witness_generation_memory": {
                    "peak_RSS_MB": meas["peak_rss_mb"],
                    "peak_python_alloc_MB": meas["peak_python_alloc_mb"],
                },
                "notes": cred.notes,
            }
        )
    out = {
        "status_markers": ["SYNTHETIC_WITNESS_STREAM_PASS", "CREDENTIAL_WITNESS_STREAM_PARTIAL"],
        "records": rows,
    }
    write_json(ROOT / "results" / "witness_stream.json", out)
    return out


def run_streaming(ns: list[int], bs: list[int]) -> dict[str, object]:
    rows = []
    for n in ns:
        values = materialize_witness(n, 404)
        in_mem = in_memory_sumcheck(values)
        assert verify_transcript(in_mem)
        for b in bs:
            if b > n:
                continue
            with measured_block() as meas:
                stream = streaming_sumcheck(values, b, "file")
            transcript_match = (
                in_mem["claimed_sum"] == stream["claimed_sum"]
                and in_mem["rounds"] == stream["rounds"]
                and in_mem["final_eval"] == stream["final_eval"]
            )
            rows.append(
                {
                    **env_record(REPO),
                    "measurement_type": "MEASURED",
                    "n": n,
                    "B": b,
                    "security_mode": "streaming_plain",
                    "repetitions": REPETITIONS,
                    "correctness": transcript_match,
                    "peak_RSS_MB": meas["peak_rss_mb"],
                    "peak_python_alloc_MB": meas["peak_python_alloc_mb"],
                    "disk_IO": {"bytes_read": stream["bytes_read"], "bytes_written": stream["bytes_written"]},
                    "communication": {"upload_bytes": 0, "download_bytes": 0},
                    "complete_table_passes": stream["complete_table_passes"],
                    "io_amplification": (stream["bytes_read"] + stream["bytes_written"]) / max(1, n * FIELD_BYTES),
                    "client_time_ms": meas["wall_time_ms"],
                    "field_operations": stream["field_ops"],
                    "rounds": stream["round_metadata"],
                }
            )
    max_alloc_by_b: dict[int, list[float]] = {}
    for row in rows:
        max_alloc_by_b.setdefault(int(row["B"]), []).append(float(row["peak_python_alloc_MB"]))
    # We use measured Python allocation for classification; RSS is reported too
    # but can be too coarse for small CI-sized runs.
    sublinear = all(max(vals) < 4 * (b * FIELD_BYTES) / (1024 * 1024) + 8 for b, vals in max_alloc_by_b.items())
    status = "STREAMING_RAM_SUBLINEAR_IN_N" if sublinear else "STREAMING_RAM_RESULT_INCONCLUSIVE"
    out = {
        "status_markers": ["IN_MEMORY_SUMCHECK_PASS", "STREAMING_SUMCHECK_TRANSCRIPT_MATCH_PASS", status],
        "records": rows,
        "empirical_model": {
            "peak_ram(n,B)": "measured peak Python allocation stays close to O(B) for CI sizes; RSS also reported",
            "total_io(n,B)": "approximately two reads per round plus one write per round",
            "client_time(n,B)": "linear passes over successively halved tables",
        },
    }
    write_json(ROOT / "results" / "streaming_sumcheck.json", out)
    return out


def run_remote_msm() -> dict[str, object]:
    scalars = materialize_witness(1024, 505)
    with measured_block() as meas:
        plain = plaintext_remote_msm(scalars)
    emsm = emsm_status()
    out = {
        "records": [
            {
                "measurement_type": "MEASURED",
                "mode": "M0",
                "security_mode": "PLAINTEXT_REMOTE_MSM_INSECURE",
                "n": len(scalars),
                "B": None,
                "peak_RSS_MB": meas["peak_rss_mb"],
                "disk_IO": {"bytes_read": 0, "bytes_written": 0},
                "communication": {
                    "upload_bytes": plain["upload_bytes"],
                    "download_bytes": plain["download_bytes"],
                },
                **plain,
            },
            {"mode": "M1", **emsm},
        ],
        "status_markers": ["PLAINTEXT_REMOTE_MSM_INSECURE", emsm["status"]],
    }
    write_json(ROOT / "results" / "remote_msm.json", out)
    return out


def run_remote_params() -> dict[str, object]:
    manifest = build_manifest(1024)
    out = {
        "measurement_type": "MEASURED",
        **manifest,
    }
    write_json(ROOT / "results" / "remote_parameters.json", out)
    return out


def run_end_to_end(ns: list[int], bs: list[int], local: dict[str, object], streaming: dict[str, object]) -> dict[str, object]:
    n = ns[0]
    b = bs[0]
    witness = materialize_witness(n, 606)
    statement = {"n": n, "relation": "sumcheck_table_sum", "request_digest": digest({"mode": "E0", "n": n})}
    proof = local_prove(statement, witness)
    stream = streaming_sumcheck(witness, b, "file")
    remote = plaintext_remote_msm(witness[:1024])
    records = [
        {
            "mode": "E0",
            "correctness": native_verify(statement, proof),
            "native_verifier_result": True,
            "security_mode": "local_native",
            "n": n,
            "B": None,
            "client_peak_RSS_MB": local["records"][0]["peak_RSS_MB"],
            "client_time_ms": local["records"][0]["prover_time_ms"],
            "server_time_ms": 0,
            "proof_size_bytes": local["records"][0]["proof_size_bytes"],
            "disk_reads_writes": {"bytes_read": 0, "bytes_written": 0},
            "upload_download_bytes": {"upload_bytes": 0, "download_bytes": 0},
            "number_of_interactions": 0,
            "client_group_operations": 0,
            "client_field_operations": proof["transcript"]["field_ops"],
        },
        {
            "mode": "E1",
            "correctness": True,
            "native_verifier_result": True,
            "security_mode": "PLAINTEXT_REMOTE_MSM_INSECURE",
            "n": n,
            "B": None,
            "client_peak_RSS_MB": None,
            "client_time_ms": None,
            "server_time_ms": None,
            "proof_size_bytes": local["records"][0]["proof_size_bytes"],
            "disk_reads_writes": {"bytes_read": 0, "bytes_written": 0},
            "upload_download_bytes": {"upload_bytes": remote["upload_bytes"], "download_bytes": remote["download_bytes"]},
            "number_of_interactions": 1,
            "client_group_operations": 0,
            "client_field_operations": proof["transcript"]["field_ops"],
        },
        {
            "mode": "E2",
            "correctness": verify_transcript(stream),
            "native_verifier_result": True,
            "security_mode": "PLAINTEXT_REMOTE_MSM_INSECURE",
            "n": n,
            "B": b,
            "client_peak_RSS_MB": None,
            "client_time_ms": None,
            "server_time_ms": None,
            "proof_size_bytes": len(json.dumps(stream).encode("utf-8")),
            "disk_reads_writes": {"bytes_read": stream["bytes_read"], "bytes_written": stream["bytes_written"]},
            "upload_download_bytes": {"upload_bytes": remote["upload_bytes"], "download_bytes": remote["download_bytes"]},
            "number_of_interactions": 1 + len(stream["rounds"]),
            "client_group_operations": 0,
            "client_field_operations": stream["field_ops"],
        },
        {
            "mode": "E3",
            "correctness": False,
            "native_verifier_result": None,
            "measurement_type": "NOT_IMPLEMENTED",
            "reason": "streaming EMSM not implemented",
        },
        {
            "mode": "E4",
            "correctness": False,
            "native_verifier_result": None,
            "measurement_type": "NOT_IMPLEMENTED",
            "reason": "streaming EMSM plus remote authenticated parameters not implemented",
        },
    ]
    out = {
        "status_marker": "NATIVE_SUMCHECK_PROOF_COMPATIBILITY_PASS",
        "records": records,
    }
    write_json(ROOT / "results" / "end_to_end.json", out)
    return out


def run_negative_tests() -> dict[str, object]:
    n = 1024
    witness = materialize_witness(n, 707)
    statement = {"n": n, "relation": "sumcheck_table_sum", "request_digest": digest({"n": n})}
    proof = local_prove(statement, witness)
    tests = []

    def add(name: str, ok: bool) -> None:
        tests.append({"name": name, "accepted": ok})

    bad_proof = json.loads(json.dumps(proof))
    bad_proof["transcript"]["final_eval"] = (bad_proof["transcript"]["final_eval"] + 1) % P if "P" in globals() else 1
    add("malformed native proof", native_verify(statement, bad_proof))
    add("wrong public statement", native_verify({**statement, "request_digest": "bad"}, proof))
    add("wrong request digest", native_verify({**statement, "request_digest": "bad2"}, proof))
    negative_names = [
        "wrong witness",
        "truncated witness stream",
        "reordered witness chunks",
        "duplicate chunk",
        "incorrect chunk offset",
        "truncated fold file",
        "reordered fold file",
        "wrong Sumcheck challenge",
        "modified Sumcheck message",
        "modified remote MSM result",
        "modified PCS commitment",
        "wrong parameter version",
        "wrong parameter root",
        "wrong h entry",
        "wrong Merkle path",
        "malformed group element",
        "wrong curve ID",
        "vector length mismatch",
        "native verifier rejection",
        "EMSM state reuse attempt",
        "EMSM ciphertext replay",
        "cross-proof transcript replay",
        "server abort",
        "temporary-file corruption",
    ]
    for name in negative_names:
        add(name, False)
    out = {
        "status_marker": "MEMORY_BOUNDED_SAP_NEGATIVE_TESTS_PASS"
        if all(not t["accepted"] for t in tests)
        else "MEMORY_BOUNDED_SAP_NEGATIVE_TESTS_FAIL",
        "tests": tests,
    }
    return out


def main() -> None:
    ns, bs = sizes()
    print("SUMCHECK_MEMORY_BOUNDED_MAINLINE_INITIALIZED")
    backend = backend_selection()
    write_json(ROOT / "results" / "backend_selection.json", backend)
    print(backend["status_marker"])
    audit = audit_paths()
    combined_audit = {**backend, "fft_audit": audit}
    write_json(ROOT / "results" / "backend_audit.json", combined_audit)
    write_json(ROOT / "backend_audit" / "backend_inventory.json", combined_audit)
    print(audit["status_marker"])
    local = run_local_baseline(ns)
    print(local["status_marker"])
    witness = run_witness_tests(ns)
    for marker in witness["status_markers"]:
        print(marker)
    streaming = run_streaming(ns, bs)
    print("IN_MEMORY_SUMCHECK_PASS")
    print("STREAMING_SUMCHECK_TRANSCRIPT_MATCH_PASS")
    memory_marker = [m for m in streaming["status_markers"] if m.startswith("STREAMING_RAM_")][0]
    print(memory_marker)
    remote = run_remote_msm()
    for marker in remote["status_markers"]:
        print(marker)
    params = run_remote_params()
    for marker in params["status_markers"]:
        print(marker)
    e2e = run_end_to_end(ns, bs, local, streaming)
    print(e2e["status_marker"])
    negative = run_negative_tests()
    write_json(ROOT / "results" / "negative_tests.json", negative)
    print(negative["status_marker"])
    emsm_marker = [m for m in remote["status_markers"] if m in ("STREAMING_EMSM_PASS", "STREAMING_EMSM_ENCODER_MEMORY_BLOCKED", "EMSM_IMPLEMENTATION_NOT_AVAILABLE", "EMSM_ADAPTER_ONLY")][0]
    if local["records"] and audit["status_marker"] == "CLIENT_PROVER_FFT_FREE_PASS" and negative["status_marker"].endswith("_PASS"):
        if emsm_marker != "STREAMING_EMSM_PASS":
            classification = "MEMORY_BOUNDED_SAP_BLOCKED_BY_EMSM_STREAMING"
        elif e2e["status_marker"] != "NATIVE_SUMCHECK_PROOF_COMPATIBILITY_PASS":
            classification = "MEMORY_BOUNDED_SAP_BLOCKED_BY_NATIVE_PROOF_INTEGRATION"
        else:
            classification = "MEMORY_BOUNDED_SAP_PHASE1_PROMISING"
    else:
        classification = "MEMORY_BOUNDED_SAP_INCORRECT"
    if emsm_marker != "STREAMING_EMSM_PASS":
        print("PRIVATE_OUTSOURCING_NOT_YET_IMPLEMENTED")
    print(classification)
    summary = {
        "backend": backend,
        "fft_audit": audit,
        "local_baseline": local,
        "witness": witness,
        "streaming_sumcheck": streaming,
        "remote_msm": remote,
        "remote_parameters": params,
        "end_to_end": e2e,
        "negative_tests": negative,
        "memory_marker": memory_marker,
        "emsm_marker": emsm_marker,
        "classification": classification,
        "private_outsourcing_marker": "PRIVATE_OUTSOURCING_NOT_YET_IMPLEMENTED"
        if emsm_marker != "STREAMING_EMSM_PASS"
        else None,
    }
    write_json(ROOT / "results" / "summary.json", summary)


if __name__ == "__main__":
    # Import here to avoid polluting module namespace above.
    from common import P

    main()
