#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common import P, hash_to_field


def basis(i: int) -> int:
    return hash_to_field("basis", i)


def plaintext_remote_msm(scalars: list[int]) -> dict[str, object]:
    acc = 0
    for i, scalar in enumerate(scalars):
        acc = (acc + scalar * basis(i)) % P
    return {
        "result": acc,
        "security_marker": "PLAINTEXT_REMOTE_MSM_INSECURE",
        "server_field_ops": 2 * len(scalars),
        "upload_bytes": 32 * len(scalars),
        "download_bytes": 32,
    }


def emsm_status() -> dict[str, object]:
    return {
        "status": "EMSM_ADAPTER_ONLY",
        "measurement_type": "NOT_IMPLEMENTED",
        "reason": "No paper-faithful streaming EMSM implementation is available in this repository.",
        "required_relation": "r=G e, v=z+r, server returns <v,g>, client recovers <z,g>=<v,g>-<e,h>",
    }
