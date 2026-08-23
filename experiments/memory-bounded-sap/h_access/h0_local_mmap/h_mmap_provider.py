from __future__ import annotations

import mmap
import time
from pathlib import Path

from common import FIELD_BYTES, P
from h_access.common.interfaces import AuthenticatedHEntry, HEntryProvider, ParameterManifest
from h_access.h0_local_mmap.h_file_format import read_header


class H0MmapProvider(HEntryProvider):
    def __init__(self, path: Path, h_batch: int = 1) -> None:
        self.path = path
        self.h_batch = h_batch
        self.header, self.body_offset = read_header(path)
        self.fh = None
        self.mm = None
        self.manifest: ParameterManifest | None = None
        self.request_digest: bytes | None = None
        self.observed_server_messages: list[dict[str, object]] = []
        self.bytes_read = 0
        self.entries_read = 0
        self.latency_ms = 0.0

    def begin_session(self, manifest: ParameterManifest, request_digest: bytes) -> None:
        self.manifest = manifest
        self.request_digest = request_digest
        self.fh = self.path.open("rb")
        self.mm = mmap.mmap(self.fh.fileno(), 0, access=mmap.ACCESS_READ)

    def fetch_entries(self, indices: list[int]) -> list[AuthenticatedHEntry]:
        if self.mm is None or self.manifest is None:
            raise ValueError("h provider session not started")
        out: list[AuthenticatedHEntry] = []
        start = time.perf_counter()
        for idx in indices:
            if not 0 <= idx < self.manifest.N:
                raise ValueError("h index out of range")
            off = self.body_offset + idx * FIELD_BYTES
            data = self.mm[off : off + FIELD_BYTES]
            if len(data) != FIELD_BYTES:
                raise ValueError("truncated h entry")
            value = int.from_bytes(data, "little")
            if value >= P:
                raise ValueError("non-canonical h entry")
            out.append(
                AuthenticatedHEntry(
                    index=idx,
                    compressed_group_element=bytes(data),
                    parameter_version=self.manifest.parameter_version,
                    vector_length=self.manifest.N,
                    curve_id=self.manifest.curve_id,
                    authentication_data={"model": "local-file-digest", "root_digest": self.manifest.root_digest},
                )
            )
            self.bytes_read += FIELD_BYTES
            self.entries_read += 1
        self.latency_ms += (time.perf_counter() - start) * 1000
        return out

    def finish_session(self) -> None:
        if self.mm is not None:
            self.mm.close()
        if self.fh is not None:
            self.fh.close()
        self.mm = None
        self.fh = None


def h0_sparse_inner_product(path: Path, manifest: ParameterManifest, entries: tuple[tuple[int, int], ...], request_digest: bytes, h_batch: int) -> tuple[int, dict[str, object]]:
    provider = H0MmapProvider(path, h_batch)
    provider.begin_session(manifest, request_digest)
    acc = 0
    try:
        for start in range(0, len(entries), h_batch):
            batch = entries[start : start + h_batch]
            fetched = provider.fetch_entries([idx for idx, _ in batch])
            for entry, (_, scalar) in zip(fetched, batch):
                value = int.from_bytes(entry.compressed_group_element, "little")
                acc = (acc + scalar * value) % P
        return acc, {
            "provider": "H0_LOCAL_MMAP",
            "h_batch": h_batch,
            "entries_read": provider.entries_read,
            "bytes_read": provider.bytes_read,
            "h_retrieval_latency_ms": provider.latency_ms,
            "server_observed_support_indices": False,
            "server_observed_messages": provider.observed_server_messages,
        }
    finally:
        provider.finish_session()

