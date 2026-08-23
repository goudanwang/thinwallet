from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Literal


ParameterClass = Literal["TEST_ONLY", "PAPER_MATCHING", "PRODUCTION_UNVALIDATED"]


@dataclass(frozen=True)
class EmsmParameters:
    security_bits: int
    input_len_n: int
    code_len_N: int
    code_rate: float
    relative_distance_target: float
    noise_weight_t: int
    malicious_mode: bool
    curve_id: str
    field_id: str
    parameter_version: str
    parameter_class: ParameterClass
    notes: list[str]

    def to_json(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class RaaParameters:
    input_len_n: int
    code_len_N: int
    repetition: int
    sigma1_a: int
    sigma1_b: int
    sigma2_a: int
    sigma2_b: int
    emsm: EmsmParameters

    def to_json(self) -> dict[str, object]:
        out = asdict(self)
        out["emsm"] = self.emsm.to_json()
        return out


def _odd_stride(seed: int, modulus_power_of_two: int) -> int:
    stride = (seed * 1103515245 + 12345) % modulus_power_of_two
    stride |= 1
    return stride


def noise_weight_for_n(n: int, security_bits: int = 128) -> int:
    # This is not a validated paper table. It avoids the forbidden O(1) setting
    # and keeps Phase 2A runtime practical while scaling with the code length.
    return max(security_bits, int(math.ceil(math.sqrt(4 * n))))


def classify_parameter(n: int) -> ParameterClass:
    if n < 2**15:
        return "TEST_ONLY"
    return "PRODUCTION_UNVALIDATED"


def make_parameters(n: int, malicious_mode: bool = False) -> RaaParameters:
    if n <= 0 or n & (n - 1):
        raise ValueError("n must be a positive power of two")
    N = 4 * n
    parameter_class = classify_parameter(n)
    notes = [
        "N=4n RAA instantiation used for Phase 2A.",
        "Noise weight scales as max(security_bits, ceil(sqrt(N))); this is not a validated production table.",
    ]
    if parameter_class == "TEST_ONLY":
        notes.append("SECURITY_PARAMETER_EXTRAPOLATED_OR_TEST_ONLY")
    else:
        notes.append("PRODUCTION_UNVALIDATED")
    emsm = EmsmParameters(
        security_bits=128,
        input_len_n=n,
        code_len_N=N,
        code_rate=n / N,
        relative_distance_target=0.25,
        noise_weight_t=noise_weight_for_n(n),
        malicious_mode=malicious_mode,
        curve_id="BN254-additive-model-test-only",
        field_id="BN254 scalar field",
        parameter_version="phase2a-raa-n4n-v1",
        parameter_class=parameter_class,
        notes=notes,
    )
    return RaaParameters(
        input_len_n=n,
        code_len_N=N,
        repetition=4,
        sigma1_a=_odd_stride(17, N),
        sigma1_b=(97 * n + 11) % N,
        sigma2_a=_odd_stride(29, N),
        sigma2_b=(131 * n + 7) % N,
        emsm=emsm,
    )


def parameter_table() -> list[dict[str, object]]:
    return [make_parameters(2**k).emsm.to_json() for k in (12, 14, 15, 16, 17, 18, 19, 20)]

