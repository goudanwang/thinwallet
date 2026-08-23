from __future__ import annotations

from dataclasses import dataclass

from emsm_real.sparse_noise import SparseNoise


@dataclass
class ClientSecretState:
    sparse_noise: SparseNoise
    used: bool = False

    def mark_used(self) -> None:
        if self.used:
            raise ValueError("reused client EMSM secret state")
        self.used = True

    def clear(self) -> None:
        self.used = True

