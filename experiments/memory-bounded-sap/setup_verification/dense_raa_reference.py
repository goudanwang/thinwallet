from __future__ import annotations

from common import P
from emsm_real.raa_encoder_reference import accumulator, permute, repetition_fold
from emsm_real.raa_parameters import RaaParameters


def dense_reference_g_alpha(params: RaaParameters, alpha: list[int]) -> list[int]:
    if len(alpha) != params.code_len_N:
        raise ValueError("alpha length mismatch")
    vec = [v % P for v in alpha]
    vec = accumulator(vec)
    vec = permute(vec, params.sigma2_a, params.sigma2_b)
    vec = accumulator(vec)
    vec = permute(vec, params.sigma1_a, params.sigma1_b)
    return repetition_fold(vec, params.repetition)

