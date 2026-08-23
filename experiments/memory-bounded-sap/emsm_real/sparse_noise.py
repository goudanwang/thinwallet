from __future__ import annotations

import hashlib
from dataclasses import dataclass

from common import P, hash_to_field
from emsm_real.raa_parameters import RaaParameters


@dataclass(frozen=True)
class SparseNoise:
    code_len_N: int
    entries: tuple[tuple[int, int], ...]
    session_id: str

    def support(self) -> list[int]:
        return [i for i, _ in self.entries]

    def to_json_public(self) -> dict[str, object]:
        return {
            "code_len_N": self.code_len_N,
            "hamming_weight": len(self.entries),
            "session_id": self.session_id,
            "support_digest": hashlib.sha256(
                ",".join(str(i) for i, _ in self.entries).encode()
            ).hexdigest(),
        }


def sample_sparse_noise(params: RaaParameters, session_id: str) -> SparseNoise:
    t = params.emsm.noise_weight_t
    entries: list[tuple[int, int]] = []
    used: set[int] = set()
    ctr = 0
    while len(entries) < t:
        idx = hash_to_field("sparse-noise-index", session_id, ctr) % params.code_len_N
        val = hash_to_field("sparse-noise-value", session_id, ctr)
        ctr += 1
        if idx in used:
            continue
        if val == 0:
            val = 1
        used.add(idx)
        entries.append((idx, val % P))
    entries.sort()
    return SparseNoise(params.code_len_N, tuple(entries), session_id)


def validate_sparse_noise(params: RaaParameters, sparse: SparseNoise) -> None:
    if sparse.code_len_N != params.code_len_N:
        raise ValueError("wrong sparse-noise code length")
    seen: set[int] = set()
    for idx, value in sparse.entries:
        if not 0 <= idx < params.code_len_N:
            raise ValueError("sparse-noise index out of range")
        if idx in seen:
            raise ValueError("duplicate sparse-noise index")
        if not 0 <= value < P:
            raise ValueError("non-canonical sparse-noise scalar")
        seen.add(idx)

