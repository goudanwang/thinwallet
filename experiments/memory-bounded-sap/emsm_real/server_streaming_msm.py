from __future__ import annotations

from common import P, hash_to_field
from emsm_real.ciphertext_stream import CiphertextStream


def make_basis(n: int, basis_version: str) -> list[int]:
    return [hash_to_field("emsm-basis", basis_version, i) for i in range(n)]


class ServerStreamingMsm:
    def __init__(self, basis: list[int], parameter_version: str, curve_id: str, request_digest: str) -> None:
        self.basis = basis
        self.parameter_version = parameter_version
        self.curve_id = curve_id
        self.request_digest = request_digest
        self.finalized = False

    def evaluate(self, stream: CiphertextStream) -> tuple[int, dict[str, object]]:
        if self.finalized:
            raise ValueError("server MSM finalized twice")
        if stream.vector_len != len(self.basis):
            raise ValueError("wrong vector length")
        if stream.request_digest != self.request_digest:
            raise ValueError("request digest mismatch")
        acc = 0
        values = stream.finalize()
        for value, base in zip(values, self.basis):
            acc = (acc + value * base) % P
        self.finalized = True
        return acc, {
            "status_marker": "STREAMING_EMSM_SERVER_EVALUATE_PASS",
            "server_field_mul": len(values),
            "server_field_add": len(values),
        }


def local_msm(z: list[int], basis: list[int]) -> int:
    return sum((a * b) % P for a, b in zip(z, basis)) % P

