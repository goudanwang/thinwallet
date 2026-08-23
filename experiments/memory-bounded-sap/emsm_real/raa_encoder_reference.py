from __future__ import annotations

from common import P
from emsm_real.raa_parameters import RaaParameters
from emsm_real.sparse_noise import SparseNoise, validate_sparse_noise


def permute(values: list[int], a: int, b: int) -> list[int]:
    n = len(values)
    out = [0] * n
    for i, value in enumerate(values):
        out[(a * i + b) % n] = value
    return out


def accumulator(values: list[int]) -> list[int]:
    out: list[int] = []
    acc = 0
    for value in values:
        acc = (acc + value) % P
        out.append(acc)
    return out


def repetition_fold(values: list[int], repetition: int) -> list[int]:
    return [sum(values[i : i + repetition]) % P for i in range(0, len(values), repetition)]


def reference_encode(params: RaaParameters, sparse: SparseNoise) -> list[int]:
    validate_sparse_noise(params, sparse)
    vec = [0] * params.code_len_N
    for idx, value in sparse.entries:
        vec[idx] = value
    vec = accumulator(vec)
    vec = permute(vec, params.sigma2_a, params.sigma2_b)
    vec = accumulator(vec)
    vec = permute(vec, params.sigma1_a, params.sigma1_b)
    return repetition_fold(vec, params.repetition)

