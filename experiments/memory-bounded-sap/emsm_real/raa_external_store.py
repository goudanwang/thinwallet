from __future__ import annotations

import os
import tempfile
from pathlib import Path

from common import FIELD_BYTES, P


def write_field(fh, value: int) -> None:
    fh.write(int(value % P).to_bytes(FIELD_BYTES, "little"))


def read_field(fh) -> int:
    data = fh.read(FIELD_BYTES)
    if len(data) != FIELD_BYTES:
        raise ValueError("truncated field store")
    return int.from_bytes(data, "little") % P


class ExternalFieldStore:
    def __init__(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="phase2a-raa-"))
        self.paths: list[Path] = []
        self.bytes_read = 0
        self.bytes_written = 0
        self.random_reads = 0
        self.sequential_reads = 0

    def path(self, name: str) -> Path:
        p = self.dir / name
        self.paths.append(p)
        return p

    def cleanup(self) -> None:
        for p in self.paths:
            p.unlink(missing_ok=True)
        try:
            self.dir.rmdir()
        except OSError:
            pass

    @property
    def temporary_storage_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.paths if p.exists())

