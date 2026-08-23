from __future__ import annotations

from dataclasses import dataclass

from common import P


@dataclass(frozen=True)
class CiphertextChunk:
    offset: int
    values: list[int]


class CiphertextStream:
    def __init__(self, vector_len: int, session_id: str, request_digest: str) -> None:
        self.vector_len = vector_len
        self.session_id = session_id
        self.request_digest = request_digest
        self.chunks: list[CiphertextChunk] = []
        self._received: set[int] = set()

    def append(self, chunk: CiphertextChunk) -> None:
        if chunk.offset in self._received:
            raise ValueError("duplicate v chunk offset")
        if chunk.offset != sum(len(c.values) for c in self.chunks):
            raise ValueError("reordered or missing v chunk")
        if chunk.offset + len(chunk.values) > self.vector_len:
            raise ValueError("v chunk beyond vector length")
        self._received.add(chunk.offset)
        self.chunks.append(CiphertextChunk(chunk.offset, [v % P for v in chunk.values]))

    def finalize(self) -> list[int]:
        out: list[int] = []
        for chunk in self.chunks:
            out.extend(chunk.values)
        if len(out) != self.vector_len:
            raise ValueError("missing v chunks")
        return out

