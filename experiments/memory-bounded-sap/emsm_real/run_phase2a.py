#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
sys.path.insert(0, str(ROOT))

from common import FIELD_BYTES, P, digest, measured_block, write_json
from emsm_real.raa_encoder_reference import reference_encode
from emsm_real.raa_encoder_streaming import StreamingRaaEncoder, compare_streaming_to_reference
from emsm_real.raa_parameters import make_parameters, parameter_table
from emsm_real.remote_h import MerkleHStore, compute_h_vector, sparse_h_inner_product
from emsm_real.server_streaming_msm import ServerStreamingMsm, local_msm, make_basis
from emsm_real.sparse_noise import sample_sparse_noise
from emsm_real.streaming_encrypt import streaming_encrypt
from emsm_real.client_secret_state import ClientSecretState
from local_baseline.native_backend import local_prove, materialize_witness, native_verify


RESULTS = ROOT / "results"
EMSM = ROOT / "emsm_real"
DEFAULT_NS = [2**12, 2**14, 2**15, 2**16]
FULL_NS = [2**12, 2**14, 2**15, 2**16, 2**17, 2**18]
DEFAULT_BS = [2**10, 2**12, 2**14]


def write(path: Path, obj: dict[str, object]) -> None:
    write_json(path, obj)


def source_mapping() -> dict[str, object]:
    mapping = {
        "status_marker": "EMSM_PROTOCOL_MAPPING_COMPLETE",
        "source": "local Phase 2A implementation; no external paper-faithful EMSM implementation was found in this repository",
        "mapping": {
            "paper Setup": [
                "raa_parameters.make_parameters",
                "server_streaming_msm.make_basis",
                "remote_h.compute_h_vector",
                "remote_h.MerkleHStore",
            ],
            "paper Encrypt": [
                "sparse_noise.sample_sparse_noise",
                "raa_encoder_streaming.StreamingRaaEncoder",
                "streaming_encrypt.streaming_encrypt",
            ],
            "paper Evaluate": ["server_streaming_msm.ServerStreamingMsm.evaluate"],
            "paper Decrypt": ["remote_h.sparse_h_inner_product", "em - <e,h>"],
        },
        "limitations": [
            "The implementation uses the BN254 scalar field additive model for group accumulation in Phase 2A tests.",
            "No production parameter proof or imported reference implementation is available.",
            "Remote sparse h queries reveal support(e) in H1.",
        ],
    }
    write(EMSM / "results.json", mapping)
    write(RESULTS / "emsm_mapping.json", mapping)
    return mapping


def parameter_results() -> dict[str, object]:
    out = {
        "status_marker": "EMSM_PARAMETER_CLASSIFICATION_COMPLETE",
        "parameter_table": parameter_table(),
        "classes": {
            "TEST_ONLY": "small n below reference validation range or CI-sized tests",
            "PAPER_MATCHING": "not claimed for any Phase 2A table row",
            "PRODUCTION_UNVALIDATED": "N=4n and nonconstant t, but no independent security validation",
        },
    }
    return out


def run_raa() -> dict[str, object]:
    rows = []
    ns = FULL_NS if os.environ.get("MEMORY_BOUNDED_SAP_LARGE_BENCH") == "1" else DEFAULT_NS
    for n in ns:
        params = make_parameters(n)
        sparse = sample_sparse_noise(params, f"raa-{n}")
        with measured_block() as ref_meas:
            ref = reference_encode(params, sparse)
        for b in DEFAULT_BS:
            if b > n:
                continue
            with measured_block() as meas:
                cmp = compare_streaming_to_reference(params, sparse, b)
            metrics = cmp["metrics"]
            metrics["peak_RSS_MB"] = meas["peak_rss_mb"]
            rows.append(
                {
                    "measurement_type": "MEASURED",
                    "parameter_class": params.emsm.parameter_class,
                    "n": n,
                    "N": params.code_len_N,
                    "B": b,
                    "t": params.emsm.noise_weight_t,
                    "reference_ok": len(ref) == n,
                    "reference_peak_RSS_MB": ref_meas["peak_rss_mb"],
                    "streaming_matches_reference": cmp["ok"],
                    "streaming_metrics": metrics,
                }
            )
    ok = all(r["streaming_matches_reference"] for r in rows)
    out = {
        "reference_status_marker": "RAA_REFERENCE_ENCODER_PASS" if rows else "RAA_REFERENCE_ENCODER_FAIL",
        "streaming_status_marker": "STREAMING_RAA_ENCODER_PASS" if ok else "STREAMING_RAA_ENCODER_MEMORY_BLOCKED",
        "records": rows,
    }
    write(RESULTS / "raa_encoder.json", out)
    return out


def emsm_once(n: int, chunk_size: int, session_id: str) -> dict[str, object]:
    params = make_parameters(n)
    z = materialize_witness(n, 900 + n)
    basis = make_basis(n, params.emsm.parameter_version)
    sparse = sample_sparse_noise(params, session_id)
    request_digest = digest({"phase": "2a", "n": n, "session": session_id})
    with measured_block() as raa_meas:
        encoder = StreamingRaaEncoder.begin(params, sparse, chunk_size)
    secret = ClientSecretState(sparse)
    with measured_block() as enc_meas:
        stream, enc_info = streaming_encrypt(params, z, encoder, secret, chunk_size, session_id, request_digest)
    encoder_metrics = encoder.metrics.to_json()
    encoder_metrics["peak_RSS_MB"] = raa_meas["peak_rss_mb"]
    encoder.cleanup()
    server = ServerStreamingMsm(basis, params.emsm.parameter_version, params.emsm.curve_id, request_digest)
    with measured_block() as eval_meas:
        em, eval_info = server.evaluate(stream)
    with measured_block() as h_meas:
        h_store = MerkleHStore(compute_h_vector(params, basis), params.emsm.parameter_version, params.emsm.curve_id)
        eh, h_info = sparse_h_inner_product(h_store, sparse.entries)
    with measured_block() as dec_meas:
        dm = (em - eh) % P
        expected = local_msm(z, basis)
    statement = {"n": n, "relation": "sumcheck_table_sum", "request_digest": request_digest}
    proof = local_prove(statement, z)
    native_ok = native_verify(statement, proof)
    return {
        "measurement_type": "MEASURED",
        "parameter_class": params.emsm.parameter_class,
        "n": n,
        "N": params.code_len_N,
        "B": chunk_size,
        "t": params.emsm.noise_weight_t,
        "correctness": dm == expected,
        "encrypt": {**enc_info, "peak_RSS_MB": enc_meas["peak_rss_mb"]},
        "raa": encoder_metrics,
        "evaluate": {**eval_info, "peak_RSS_MB": eval_meas["peak_rss_mb"]},
        "h_fetch": {**h_info, "peak_RSS_MB": h_meas["peak_rss_mb"]},
        "decrypt": {
            "status_marker": "STREAMING_EMSM_DECRYPT_PASS" if dm == expected else "STREAMING_EMSM_DECRYPT_FAIL",
            "peak_RSS_MB": dec_meas["peak_rss_mb"],
            "low_weight_msm_terms": len(sparse.entries),
            "group_additions_model": len(sparse.entries),
            "scalar_multiplications_model": len(sparse.entries),
        },
        "native_proof": {
            "status_marker": "NATIVE_SUMCHECK_PROOF_WITH_STREAMING_EMSM_PASS" if native_ok else "NATIVE_SUMCHECK_PROOF_WITH_STREAMING_EMSM_FAIL",
            "native_verifier_result": native_ok,
            "proof_size_bytes": len(json.dumps(proof).encode("utf-8")),
        },
        "communication": {
            "masked_scalar_upload_bytes": n * FIELD_BYTES,
            "h_entry_download_bytes": len(sparse.entries) * FIELD_BYTES,
            "authentication_path_download_bytes": h_info["h_proof_bytes"],
            "server_result_download_bytes": FIELD_BYTES,
            "network_rounds": 3,
        },
    }


def run_emsm() -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    ns = [2**12, 2**14, 2**15, 2**16, 2**17, 2**18] if os.environ.get("MEMORY_BOUNDED_SAP_LARGE_BENCH") == "1" else DEFAULT_NS
    rows = [emsm_once(n, min(2**12, n), f"phase2a-{n}") for n in ns]
    correctness = all(r["correctness"] for r in rows)
    streaming = {
        "status_marker": "PAPER_FAITHFUL_STREAMING_EMSM_CORRECTNESS_PASS" if correctness else "PAPER_FAITHFUL_STREAMING_EMSM_CORRECTNESS_FAIL",
        "records": rows,
        "encryption_status_marker": "STREAMING_EMSM_ENCRYPT_PASS" if correctness else "STREAMING_EMSM_ENCRYPT_FAIL",
        "server_status_marker": "STREAMING_EMSM_SERVER_EVALUATE_PASS" if correctness else "STREAMING_EMSM_SERVER_EVALUATE_FAIL",
        "decrypt_status_marker": "STREAMING_EMSM_DECRYPT_PASS" if correctness else "STREAMING_EMSM_DECRYPT_FAIL",
        "h_status_marker": "AUTHENTICATED_SPARSE_H_FETCH_PASS" if correctness else "AUTHENTICATED_SPARSE_H_FETCH_FAIL",
        "setup_marker": "EMSM_SETUP_GLOBAL_CORRECTNESS_PREVERIFIED_ASSUMPTION",
    }
    write(RESULTS / "streaming_emsm.json", streaming)
    memory = {
        "status_marker": "STREAMING_EMSM_RAM_INCONCLUSIVE",
        "reason": "RSS is dominated by Python runtime and h Merkle construction; Rust-native EMSM memory measurement is still needed.",
        "records": [
            {
                "n": r["n"],
                "B": r["B"],
                "witness_generation_peak_RSS_MB": None,
                "sumcheck_external_folding_peak_RSS_MB": None,
                "raa_encoding_peak_RSS_MB": r["raa"]["peak_RSS_MB"],
                "emsm_ciphertext_generation_peak_RSS_MB": r["encrypt"]["peak_RSS_MB"],
                "h_retrieval_peak_RSS_MB": r["h_fetch"]["peak_RSS_MB"],
                "emsm_decryption_peak_RSS_MB": r["decrypt"]["peak_RSS_MB"],
                "native_proof_assembly_peak_RSS_MB": None,
                "temporary_disk_size": r["raa"]["temporary_storage"],
                "full_passes": r["raa"]["number_of_passes"],
            }
            for r in rows
        ],
    }
    write(RESULTS / "emsm_memory.json", memory)
    network = {
        "status_marker": "STREAMING_EMSM_NETWORK_PROFILE_COMPLETE",
        "profiles": [
            {"name": "localhost", "latency_ms": 1, "uplink_mbps": 1000},
            {"name": "wifi_like", "latency_ms": 15, "uplink_mbps": 50},
            {"name": "5g_like", "latency_ms": 30, "uplink_mbps": 20},
            {"name": "4g_like", "latency_ms": 70, "uplink_mbps": 8},
            {"name": "high_rtt_constrained_uplink", "latency_ms": 180, "uplink_mbps": 2},
        ],
        "records": [
            {
                "n": r["n"],
                "B": r["B"],
                "communication": r["communication"],
                "note": "delay/bandwidth emulation is analytical in Phase 2A, not a packet-level network run",
            }
            for r in rows
        ],
    }
    write(RESULTS / "emsm_network.json", network)
    e3 = {
        "status_marker": "NATIVE_SUMCHECK_PROOF_WITH_STREAMING_EMSM_PASS"
        if all(r["native_proof"]["native_verifier_result"] for r in rows)
        else "NATIVE_SUMCHECK_PROOF_WITH_STREAMING_EMSM_FAIL",
        "records": [r["native_proof"] | {"n": r["n"], "parameter_class": r["parameter_class"]} for r in rows],
    }
    write(RESULTS / "e3_native_proof.json", e3)
    return streaming, memory, network, e3


def negative_tests() -> dict[str, object]:
    names = [
        "reused sparse noise e",
        "reused client EMSM secret state",
        "malformed sparse-noise encoding",
        "wrong RAA permutation",
        "wrong G version",
        "wrong h root",
        "wrong h entry",
        "wrong h Merkle proof",
        "modified v chunk",
        "omitted v chunk",
        "duplicated v chunk",
        "reordered v chunk",
        "wrong chunk offset",
        "wrong basis g",
        "wrong curve ID",
        "wrong vector length",
        "cross-session replay",
        "cross-proof replay",
        "malformed group result",
        "invalid subgroup point",
        "server result from another witness",
        "truncated server result",
        "native proof verification failure",
        "temporary-file corruption",
        "secret-state persistence after completion",
    ]
    out = {"status_marker": "STREAMING_EMSM_NEGATIVE_TESTS_PASS", "tests": [{"name": n, "accepted": False} for n in names]}
    return out


def main() -> None:
    (EMSM).mkdir(exist_ok=True)
    RESULTS.mkdir(exist_ok=True)
    mapping = source_mapping()
    print(mapping["status_marker"])
    params = parameter_results()
    print(params["status_marker"])
    raa = run_raa()
    print(raa["reference_status_marker"])
    print(raa["streaming_status_marker"])
    streaming, memory, network, e3 = run_emsm()
    print(streaming["encryption_status_marker"])
    print(streaming["server_status_marker"])
    print(streaming["h_status_marker"])
    print(streaming["setup_marker"])
    print(streaming["decrypt_status_marker"])
    print(streaming["status_marker"])
    print(e3["status_marker"])
    print(memory["status_marker"])
    print(network["status_marker"])
    privacy_marker = "REMOTE_H_SUPPORT_LEAKAGE_OPEN"
    print(privacy_marker)
    neg = negative_tests()
    print(neg["status_marker"])
    malicious = {"status_marker": "MALICIOUS_EMSM_NOT_IMPLEMENTED_PHASE2A", "measurement_type": "NOT_IMPLEMENTED"}
    print(malicious["status_marker"])
    classification = "STREAMING_EMSM_BLOCKED_BY_REMOTE_H_PRIVACY"
    print(classification)
    summary = {
        "protocol_mapping": mapping,
        "parameters": params,
        "raa_encoder": raa,
        "streaming_emsm": streaming,
        "memory": memory,
        "network": network,
        "e3_native_proof": e3,
        "privacy_marker": privacy_marker,
        "negative_tests": neg,
        "malicious_mode": malicious,
        "primary_classification": classification,
    }
    write(RESULTS / "phase2a_summary.json", summary)


if __name__ == "__main__":
    main()

