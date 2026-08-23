#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common import digest, hash_to_field


def merkle_parent(left: str, right: str) -> str:
    return digest({"left": left, "right": right})


def build_manifest(length: int, version: str = "phase1") -> dict[str, object]:
    leaves = [digest({"index": i, "value": hash_to_field("h", i)}) for i in range(length)]
    level = leaves[:]
    if len(level) & (len(level) - 1):
        raise ValueError("length must be power of two")
    while len(level) > 1:
        level = [merkle_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return {
        "ParameterManifest": {
            "parameter_version": version,
            "curve_id": "BN254-scalar-toy",
            "backend_id": "INTERNAL_FFT_FREE_MULTILINEAR_SUMCHECK_PHASE1_BACKEND",
            "vector_length": length,
            "MerkleRoot": level[0],
            "ChunkDigest": digest(leaves),
        },
        "status_markers": [
            "REMOTE_PARAMETER_STORAGE_PASS",
            "EMSM_SETUP_GLOBAL_CORRECTNESS_ASSUMED_OR_PREVERIFIED",
        ],
    }
