from __future__ import annotations

import hashlib
from dataclasses import dataclass

from common import FIELD_BYTES, P
from emsm_real.raa_parameters import RaaParameters


def _permute_transpose(values: list[int], a: int, b: int) -> list[int]:
    n = len(values)
    return [values[(a * i + b) % n] for i in range(n)]


def _accumulator_transpose(values: list[int]) -> list[int]:
    out = [0] * len(values)
    acc = 0
    for i in range(len(values) - 1, -1, -1):
        acc = (acc + values[i]) % P
        out[i] = acc
    return out


def compute_h_vector(params: RaaParameters, basis: list[int]) -> list[int]:
    if len(basis) != params.input_len_n:
        raise ValueError("wrong basis length")
    vec: list[int] = []
    for b in basis:
        vec.extend([b] * params.repetition)
    vec = _permute_transpose(vec, params.sigma1_a, params.sigma1_b)
    vec = _accumulator_transpose(vec)
    vec = _permute_transpose(vec, params.sigma2_a, params.sigma2_b)
    vec = _accumulator_transpose(vec)
    return vec


def leaf_hash(index: int, value: int) -> bytes:
    return hashlib.sha256(b"leaf" + index.to_bytes(8, "little") + int(value % P).to_bytes(FIELD_BYTES, "little")).digest()


def pair_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"node" + left + right).digest()


@dataclass
class MerkleHStore:
    h: list[int]
    parameter_version: str
    curve_id: str

    def __post_init__(self) -> None:
        level = [leaf_hash(i, v) for i, v in enumerate(self.h)]
        self.levels = [level]
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            level = [pair_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
            self.levels.append(level)

    @property
    def root(self) -> str:
        return self.levels[-1][0].hex()

    def fetch(self, index: int) -> tuple[int, list[str]]:
        if not 0 <= index < len(self.h):
            raise ValueError("h index out of range")
        proof: list[str] = []
        pos = index
        for level in self.levels[:-1]:
            sib = pos ^ 1
            if sib >= len(level):
                sib = len(level) - 1
            proof.append(level[sib].hex())
            pos //= 2
        return self.h[index], proof


def verify_h_proof(index: int, value: int, proof: list[str], root: str) -> bool:
    cur = leaf_hash(index, value)
    pos = index
    for sibling_hex in proof:
        sibling = bytes.fromhex(sibling_hex)
        if pos % 2 == 0:
            cur = pair_hash(cur, sibling)
        else:
            cur = pair_hash(sibling, cur)
        pos //= 2
    return cur.hex() == root


def sparse_h_inner_product(store: MerkleHStore, entries: tuple[tuple[int, int], ...]) -> tuple[int, dict[str, object]]:
    acc = 0
    proof_bytes = 0
    for index, scalar in entries:
        value, proof = store.fetch(index)
        if not verify_h_proof(index, value, proof, store.root):
            raise ValueError("invalid h Merkle proof")
        proof_bytes += 32 * len(proof)
        acc = (acc + scalar * value) % P
    return acc, {
        "status_marker": "AUTHENTICATED_SPARSE_H_FETCH_PASS",
        "fetched_h_entries": len(entries),
        "h_proof_bytes": proof_bytes,
        "h_root": store.root,
    }

