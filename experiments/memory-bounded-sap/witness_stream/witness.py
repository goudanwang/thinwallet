#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common import FieldChunk, witness_prf


class SyntheticWitnessSource:
    def __init__(self, n: int, seed: int, domain: str = "synthetic") -> None:
        self.n = n
        self.seed = seed
        self.domain = domain
        self.pos = 0

    def len(self) -> int:
        return self.n

    def reset(self) -> None:
        self.pos = 0

    def next_chunk(self, max_items: int) -> FieldChunk | None:
        if self.pos >= self.n:
            return None
        count = min(max_items, self.n - self.pos)
        offset = self.pos
        values = [witness_prf(self.seed, i, self.domain) for i in range(offset, offset + count)]
        self.pos += count
        return FieldChunk(offset=offset, values=values)


class CredentialLikeWitnessSource(SyntheticWitnessSource):
    def __init__(self, n: int, seed: int) -> None:
        super().__init__(n=n, seed=seed, domain="credential-like")
        self.live_state_bytes = 4096
        self.status = "CREDENTIAL_WITNESS_STREAM_PARTIAL"
        self.notes = [
            "Issuer-signature verification is modeled as deterministic field emissions in Phase 1.",
            "A real credential circuit backend is not integrated yet.",
            "The generator emits values in circuit order without retaining the full trace.",
        ]
