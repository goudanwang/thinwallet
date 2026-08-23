#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common import digest, measured_block
from streaming_sumcheck.sumcheck import in_memory_sumcheck, verify_transcript
from witness_stream.witness import SyntheticWitnessSource


def materialize_witness(n: int, seed: int) -> list[int]:
    source = SyntheticWitnessSource(n, seed)
    values: list[int] = []
    while True:
        chunk = source.next_chunk(4096)
        if chunk is None:
            return values
        values.extend(chunk.values)


def local_prove(statement: dict[str, object], witness: list[int]) -> dict[str, object]:
    transcript = in_memory_sumcheck(witness)
    return {
        "backend": "INTERNAL_FFT_FREE_MULTILINEAR_SUMCHECK_PHASE1_BACKEND",
        "statement": statement,
        "transcript": transcript,
        "proof_digest": digest({"statement": statement, "transcript": transcript}),
    }


def native_verify(statement: dict[str, object], proof: dict[str, object]) -> bool:
    if proof.get("statement") != statement:
        return False
    transcript = proof.get("transcript")
    return isinstance(transcript, dict) and verify_transcript(transcript)
