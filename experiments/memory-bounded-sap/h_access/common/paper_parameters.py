from __future__ import annotations

import math

FIELD_BYTES = 32


def paper_t(n: int, security_bits: int, delta: float = 0.05) -> int:
    N = 4 * n
    raw = math.log(2) * (security_bits - math.log2(N)) / delta
    return max(1, math.ceil(raw))


def classify(n: int, security_bits: int) -> str:
    if security_bits == 100:
        return "PAPER_MATCHING_100_BIT"
    if security_bits == 128:
        return "PAPER_MATCHING_128_BIT"
    return "PRODUCTION_UNVALIDATED"


def parameter_table(ns: list[int] | None = None, lambdas: tuple[int, ...] = (100, 128)) -> list[dict[str, object]]:
    if ns is None:
        ns = [2**k for k in (12, 14, 15, 16, 17, 18, 19, 20)]
    rows: list[dict[str, object]] = []
    for n in ns:
        N = 4 * n
        for lam in lambdas:
            t = paper_t(n, lam)
            rows.append(
                {
                    "measurement_type": "ESTIMATED",
                    "parameter_class": classify(n, lam),
                    "n": n,
                    "N": N,
                    "lambda": lam,
                    "delta": 0.05,
                    "t": t,
                    "estimated_h_size_bytes": N * FIELD_BYTES,
                    "estimated_sparse_correction_cost": {
                        "h_entries": t,
                        "scalar_multiplications": t,
                        "group_additions": t,
                    },
                    "distance_assumption": "PARAMETER_DISTANCE_ASSUMPTION_EXTRAPOLATED",
                }
            )
    return rows

