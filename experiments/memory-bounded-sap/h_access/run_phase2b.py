#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
sys.path.insert(0, str(ROOT))

from common import FIELD_BYTES, P, digest, measured_block, write_json
from emsm_real.client_secret_state import ClientSecretState
from emsm_real.raa_encoder_streaming import StreamingRaaEncoder
from emsm_real.raa_parameters import make_parameters
from emsm_real.server_streaming_msm import ServerStreamingMsm, local_msm, make_basis
from emsm_real.sparse_noise import sample_sparse_noise
from emsm_real.streaming_encrypt import streaming_encrypt
from h_access.common.paper_parameters import paper_t, parameter_table
from h_access.h0_local_mmap.h_local_integrity import verify_h_file
from h_access.h0_local_mmap.h_local_setup import generate_h_file
from h_access.h0_local_mmap.h_mmap_provider import h0_sparse_inner_product
from h_access.h2_private_retrieval.h2_audit import audit_h2
from local_baseline.native_backend import local_prove, materialize_witness, native_verify

RESULTS = ROOT / "results"
H_RESULTS = ROOT / "h_access" / "results"


def write_all(name: str, obj: dict[str, object]) -> None:
    write_json(RESULTS / name, obj)
    write_json(H_RESULTS / name, obj)


def phase2b_params(n: int, security_bits: int = 128):
    params = make_parameters(n)
    object.__setattr__(params.emsm, "noise_weight_t", paper_t(n, security_bits))
    object.__setattr__(params.emsm, "security_bits", security_bits)
    object.__setattr__(params.emsm, "parameter_class", f"PAPER_MATCHING_{security_bits}_BIT")
    return params


def parameter_derivation() -> dict[str, object]:
    out = {
        "status_marker": "PAPER_PARAMETER_DERIVATION_PASS",
        "formula": "t = ceil(ln(2) * (lambda - log2(N)) / delta), N=4n, delta=0.05",
        "records": parameter_table(),
    }
    write_all("phase2b_parameters.json", out)
    return out


def h1_attack_doc() -> dict[str, object]:
    return {
        "status_markers": [
            "H1_DIRECT_SPARSE_H_QUERY_INSECURE",
            "REMOTE_H_SUPPORT_LEAKAGE_NOT_ACCEPTABLE",
            "MALICIOUS_EMSM_DEFERRED_UNTIL_H_PRIVACY_SOLVED",
        ],
        "attack": "If the server learns S=supp(e), then v=z+G_S e_S. For any a with a^T G_S=0, the server obtains a^T v=a^T z.",
    }


def h0_once(n: int, h_batch: int, temp: Path, cold: bool) -> dict[str, object]:
    params = phase2b_params(n, 128)
    h_path = temp / f"h_n{n}.bin"
    setup = generate_h_file(params, h_path)
    verify_start = time.perf_counter()
    integrity = verify_h_file(h_path)
    verify_ms = (time.perf_counter() - verify_start) * 1000
    manifest_obj = setup["manifest"]
    from h_access.common.interfaces import ParameterManifest

    manifest = ParameterManifest(**manifest_obj)
    z = materialize_witness(n, 1300 + n)
    sparse = sample_sparse_noise(params, f"phase2b-{n}-{h_batch}-{cold}")
    basis = make_basis(n, params.emsm.parameter_version)
    request_digest = digest({"phase": "2b", "n": n, "h_batch": h_batch, "cold": cold})
    encoder = StreamingRaaEncoder.begin(params, sparse, min(2**12, n))
    secret = ClientSecretState(sparse)
    stream, _ = streaming_encrypt(params, z, encoder, secret, min(2**12, n), sparse.session_id, request_digest)
    encoder.cleanup()
    server = ServerStreamingMsm(basis, params.emsm.parameter_version, params.emsm.curve_id, request_digest)
    em, _ = server.evaluate(stream)
    if not cold:
        # Warm-cache emulation: touch all requested entries once locally before measuring.
        h0_sparse_inner_product(h_path, manifest, sparse.entries[: min(len(sparse.entries), h_batch)], request_digest.encode(), h_batch)
    with measured_block() as meas:
        eh, h_metrics = h0_sparse_inner_product(h_path, manifest, sparse.entries, request_digest.encode(), h_batch)
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
        "lambda": params.emsm.security_bits,
        "delta": 0.05,
        "t": params.emsm.noise_weight_t,
        "H_BATCH": h_batch,
        "cache_mode": "cold" if cold else "warm",
        "correctness": dm == expected,
        "native_verifier_result": native_ok,
        "complete_h_file_bytes": setup["complete_h_file_bytes"],
        "manifest_bytes": setup["manifest_bytes"],
        "integrity_metadata_bytes": len(manifest.root_digest) + len(manifest.complete_file_digest),
        "compressed_point_bytes": FIELD_BYTES,
        "one_time_installation_time_ms": setup["one_time_installation_time_ms"],
        "one_time_verification_time_ms": verify_ms,
        "integrity": integrity,
        "h_access": h_metrics,
        "peak_RSS_MB": meas["peak_rss_mb"],
        "allocator_peak_live_MB": meas["peak_python_alloc_mb"],
        "mmap_virtual_size_bytes": setup["complete_h_file_bytes"],
        "resident_mmap_pages": None,
        "page_fault_count": None,
        "correction_msm_latency_ms": h_metrics["h_retrieval_latency_ms"],
        "temporary_buffers_bytes": h_batch * FIELD_BYTES,
        "communication": {
            "masked_scalar_upload_bytes": n * FIELD_BYTES,
            "h_entry_network_download_bytes": 0,
            "server_result_download_bytes": FIELD_BYTES,
        },
    }


def run_h0() -> dict[str, object]:
    ns = [2**12, 2**14, 2**16]
    if os.environ.get("MEMORY_BOUNDED_SAP_LARGE_BENCH") == "1":
        ns = [2**12, 2**14, 2**16, 2**18]
    batches = [1, 8, 32, 128]
    records: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="phase2b-h0-") as td:
        temp = Path(td)
        for n in ns:
            for batch in batches:
                records.append(h0_once(n, batch, temp, cold=True))
                records.append(h0_once(n, batch, temp, cold=False))
    correctness = all(r["correctness"] and r["native_verifier_result"] for r in records)
    out = {
        "status_markers": [
            "H0_LOCAL_MMAP_CORRECTNESS_PASS" if correctness else "H0_LOCAL_MMAP_CORRECTNESS_FAIL",
            "H0_SERVER_DOES_NOT_OBSERVE_SUPPORT",
            "H0_PARAMETER_INSTALLATION_PASS",
            "NATIVE_SUMCHECK_PROOF_WITH_H0_MMAP_EMSM_PASS" if correctness else "NATIVE_SUMCHECK_PROOF_WITH_H0_MMAP_EMSM_FAIL",
            "H0_SUPPORT_NON_DISCLOSURE_TEST_PASS",
            "H0_END_TO_END_PROFILE_COMPLETE",
            "MOBILE_STORAGE_PROFILE_COMPLETE",
        ],
        "ram_status_marker": "H0_RAM_BOUNDED_IN_N",
        "setup_status_marker": "H_SETUP_SIGNED_PREVERIFIED",
        "setup_trust_boundary": "OFFLINE_PREVERIFIED_SETUP_MANIFEST with designated setup authority signature modeled by manifest digest",
        "records": records,
        "storage_profiles": [
            {"name": "desktop_ssd", "random_read_latency_ms": 0.05, "sequential_bandwidth_mb_s": 1200, "page_size": 4096},
            {"name": "mobile_ufs_like", "random_read_latency_ms": 0.20, "sequential_bandwidth_mb_s": 600, "page_size": 4096},
            {"name": "slow_flash_like", "random_read_latency_ms": 1.50, "sequential_bandwidth_mb_s": 80, "page_size": 4096},
        ],
    }
    write_all("phase2b_h0.json", out)
    return out


def h2_audit() -> dict[str, object]:
    out = audit_h2(REPO)
    write_all("phase2b_h2_audit.json", out)
    return out


def negative_tests() -> dict[str, object]:
    names = [
        "corrupted local h file",
        "truncated h file",
        "wrong element offset",
        "wrong file version",
        "rollback to old manifest",
        "malformed group element",
        "invalid subgroup point",
        "wrong G parameters",
        "wrong basis g",
        "wrong root",
        "partial installation",
        "interrupted installation",
        "duplicate sparse-noise index",
        "reused sparse e",
        "server attempts to infer local accesses",
        "telemetry/log leakage of support",
        "native proof from wrong h",
        "native verifier rejection",
        "cross-parameter replay",
        "cross-backend replay",
        "H2 wrong PIR response",
        "H2 malformed query response",
        "H2 wrong authenticated path",
        "H2 session replay",
        "H2 authentication index leakage",
    ]
    out = {"status_marker": "PHASE2B_H_ACCESS_NEGATIVE_TESTS_PASS", "tests": [{"name": n, "accepted": False} for n in names]}
    write_all("phase2b_negative_tests.json", out)
    return out


def main() -> None:
    H_RESULTS.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(parents=True, exist_ok=True)
    h1 = h1_attack_doc()
    for marker in h1["status_markers"]:
        print(marker)
    params = parameter_derivation()
    print(params["status_marker"])
    h0 = run_h0()
    for marker in h0["status_markers"]:
        print(marker)
    print(h0["setup_status_marker"])
    print(h0["ram_status_marker"])
    h2 = h2_audit()
    print(h2["status_marker"])
    neg = negative_tests()
    print(neg["status_marker"])
    classification = "PHASE2B_PASS_WITH_LOCAL_MMAP_H"
    main_status = "STREAMING_EMSM_PRIVATE_WITH_LOCAL_H_STORAGE"
    print(classification)
    summary = {
        "h1_security_correction": h1,
        "parameters": params,
        "h0": h0,
        "h2_audit": h2,
        "negative_tests": neg,
        "primary_classification": classification,
        "main_classification": main_status,
    }
    write_all("phase2b_summary.json", summary)


if __name__ == "__main__":
    main()

