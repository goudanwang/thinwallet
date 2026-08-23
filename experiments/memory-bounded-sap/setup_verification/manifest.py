from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from common import FIELD_BYTES
from emsm_real.raa_parameters import RaaParameters
from emsm_real.server_streaming_msm import make_basis
from h_access.h0_local_mmap.h_file_format import read_manifest


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def field_vector_digest(values: list[int]) -> str:
    h = hashlib.sha256()
    for v in values:
        h.update(int(v).to_bytes(FIELD_BYTES, "little"))
    return h.hexdigest()


@dataclass(frozen=True)
class SetupParameterManifest:
    protocol_version: str
    backend_id: str
    curve_id: str
    field_id: str
    n: int
    N: int
    G_parameters: dict[str, int]
    sigma_1_digest: str
    sigma_2_digest: str
    root_g: str
    root_h: str
    encoding_size: int
    setup_generation_version: str
    parameter_version: str

    def canonical_bytes(self) -> bytes:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()

    def digest(self) -> str:
        return digest_bytes(self.canonical_bytes())


def permutation_digest(a: int, b: int, N: int) -> str:
    return digest_bytes(json.dumps({"a": a, "b": b, "N": N}, sort_keys=True).encode())


def build_setup_manifest(params: RaaParameters, h_file) -> tuple[SetupParameterManifest, list[int]]:
    basis = make_basis(params.input_len_n, params.emsm.parameter_version)
    h_manifest = read_manifest(h_file)
    manifest = SetupParameterManifest(
        protocol_version="phase2c-setup-v1",
        backend_id="INTERNAL_FFT_FREE_MULTILINEAR_SUMCHECK_PHASE1_BACKEND",
        curve_id=params.emsm.curve_id,
        field_id=params.emsm.field_id,
        n=params.input_len_n,
        N=params.code_len_N,
        G_parameters={
            "repetition": params.repetition,
            "sigma1_a": params.sigma1_a,
            "sigma1_b": params.sigma1_b,
            "sigma2_a": params.sigma2_a,
            "sigma2_b": params.sigma2_b,
        },
        sigma_1_digest=permutation_digest(params.sigma1_a, params.sigma1_b, params.code_len_N),
        sigma_2_digest=permutation_digest(params.sigma2_a, params.sigma2_b, params.code_len_N),
        root_g=field_vector_digest(basis),
        root_h=h_manifest.root_digest,
        encoding_size=FIELD_BYTES,
        setup_generation_version="phase2b-h0-v1",
        parameter_version=params.emsm.parameter_version,
    )
    return manifest, basis

