#!/usr/bin/env python3
from __future__ import annotations

import os
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common import FIELD_BYTES, P, FieldChunk, digest, hash_to_field, measured_block


class FoldStore(Protocol):
    def len(self) -> int: ...
    def read_chunk(self, offset: int, length: int) -> FieldChunk: ...
    def append_chunk(self, chunk: FieldChunk) -> None: ...
    def finish_round(self) -> None: ...
    def cleanup(self) -> None: ...


def challenge(prefix: list[dict[str, int]], alpha: int, beta: int) -> int:
    c = hash_to_field("phase1-sumcheck", prefix, alpha, beta)
    return c if c != 0 else 1


def fold_pair(a: int, b: int, r: int) -> int:
    return ((1 - r) * a + r * b) % P


def pack(values: list[int]) -> bytes:
    return b"".join(int(v % P).to_bytes(FIELD_BYTES, "little") for v in values)


def unpack(data: bytes) -> list[int]:
    if len(data) % FIELD_BYTES:
        raise ValueError("truncated field file")
    return [int.from_bytes(data[i : i + FIELD_BYTES], "little") % P for i in range(0, len(data), FIELD_BYTES)]


class MemoryFoldStore:
    def __init__(self, values: list[int]) -> None:
        self.values = values[:]
        self.next_values: list[int] = []
        self.round_metadata: list[dict[str, object]] = []

    def len(self) -> int:
        return len(self.values)

    def read_chunk(self, offset: int, length: int) -> FieldChunk:
        return FieldChunk(offset=offset, values=self.values[offset : offset + length])

    def append_chunk(self, chunk: FieldChunk) -> None:
        if chunk.offset != len(self.next_values):
            raise ValueError("reordered memory fold chunk")
        self.next_values.extend(chunk.values)

    def finish_round(self) -> None:
        self.round_metadata.append({"len": len(self.next_values), "checksum": digest(self.next_values)})
        self.values, self.next_values = self.next_values, []

    def cleanup(self) -> None:
        return None


class FileFoldStore:
    def __init__(self, values: list[int], temp_dir: Path | None = None) -> None:
        self.temp = Path(tempfile.mkdtemp(prefix="mbsap-fold-", dir=temp_dir))
        self.current = self.temp / "round_0.bin"
        self.next = self.temp / "round_next.bin"
        self.current.write_bytes(pack(values))
        self.round_no = 0
        self.next_count = 0
        self.bytes_read = 0
        self.bytes_written = len(values) * FIELD_BYTES
        self.round_metadata: list[dict[str, object]] = []

    def len(self) -> int:
        return self.current.stat().st_size // FIELD_BYTES

    def read_chunk(self, offset: int, length: int) -> FieldChunk:
        with self.current.open("rb") as fh:
            fh.seek(offset * FIELD_BYTES)
            data = fh.read(length * FIELD_BYTES)
        self.bytes_read += len(data)
        values = unpack(data)
        if len(values) != length:
            raise ValueError("truncated fold file")
        return FieldChunk(offset=offset, values=values)

    def append_chunk(self, chunk: FieldChunk) -> None:
        if chunk.offset != self.next_count:
            raise ValueError("reordered fold file")
        mode = "ab" if self.next.exists() else "wb"
        data = pack(chunk.values)
        with self.next.open(mode) as fh:
            fh.write(data)
        self.bytes_written += len(data)
        self.next_count += len(chunk.values)

    def finish_round(self) -> None:
        checksum = digest(self.next.read_bytes().hex()) if self.next.exists() else digest("")
        self.round_metadata.append({"round": self.round_no, "len": self.next_count, "checksum": checksum})
        self.current.unlink(missing_ok=True)
        self.next.rename(self.current)
        self.next = self.temp / "round_next.bin"
        self.next_count = 0
        self.round_no += 1

    def cleanup(self) -> None:
        for p in self.temp.glob("*"):
            p.unlink(missing_ok=True)
        self.temp.rmdir()


def in_memory_sumcheck(values: list[int]) -> dict[str, object]:
    table = values[:]
    prefix: list[dict[str, int]] = []
    rounds: list[dict[str, int]] = []
    field_ops = 0
    while len(table) > 1:
        g0 = sum(table[0::2]) % P
        g1 = sum(table[1::2]) % P
        alpha = (g1 - g0) % P
        beta = g0
        r = challenge(prefix, alpha, beta)
        rounds.append({"alpha": alpha, "beta": beta, "challenge": r})
        prefix.append(rounds[-1])
        table = [fold_pair(table[i], table[i + 1], r) for i in range(0, len(table), 2)]
        field_ops += len(table) * 4
    return {
        "claimed_sum": sum(values) % P,
        "rounds": rounds,
        "final_eval": table[0] if table else 0,
        "field_ops": field_ops,
    }


def verify_transcript(transcript: dict[str, object]) -> bool:
    expected = int(transcript["claimed_sum"]) % P
    prefix: list[dict[str, int]] = []
    for round_obj in transcript["rounds"]:
        alpha = int(round_obj["alpha"]) % P
        beta = int(round_obj["beta"]) % P
        r = int(round_obj["challenge"]) % P
        if (2 * beta + alpha) % P != expected:
            return False
        if r != challenge(prefix, alpha, beta):
            return False
        prefix.append({"alpha": alpha, "beta": beta, "challenge": r})
        expected = (alpha * r + beta) % P
    return expected == int(transcript["final_eval"]) % P


def streaming_sumcheck(values: list[int], b: int, store_kind: str) -> dict[str, object]:
    store: MemoryFoldStore | FileFoldStore
    store = MemoryFoldStore(values) if store_kind == "memory" else FileFoldStore(values)
    prefix: list[dict[str, int]] = []
    rounds: list[dict[str, object]] = []
    total_field_ops = 0
    total_bytes_read = 0
    total_bytes_written = len(values) * FIELD_BYTES if store_kind == "file" else 0
    try:
        while store.len() > 1:
            input_len = store.len()
            g0 = 0
            g1 = 0
            offset = 0
            while offset < input_len:
                length = min(b if b % 2 == 0 else b - 1, input_len - offset)
                if length % 2:
                    length -= 1
                chunk = store.read_chunk(offset, length)
                vals = chunk.values
                g0 = (g0 + sum(vals[0::2])) % P
                g1 = (g1 + sum(vals[1::2])) % P
                offset += length
            alpha = (g1 - g0) % P
            beta = g0
            r = challenge(prefix, alpha, beta)
            msg = {"alpha": alpha, "beta": beta, "challenge": r}
            prefix.append(msg)
            out_offset = 0
            offset = 0
            while offset < input_len:
                length = min(b if b % 2 == 0 else b - 1, input_len - offset)
                if length % 2:
                    length -= 1
                chunk = store.read_chunk(offset, length)
                vals = chunk.values
                folded = [fold_pair(vals[i], vals[i + 1], r) for i in range(0, len(vals), 2)]
                store.append_chunk(FieldChunk(offset=out_offset, values=folded))
                out_offset += len(folded)
                offset += length
            store.finish_round()
            field_ops = (input_len // 2) * 4
            total_field_ops += field_ops
            file_read = getattr(store, "bytes_read", 0)
            file_written = getattr(store, "bytes_written", 0)
            rounds.append(
                {
                    "input_length": input_len,
                    "output_length": input_len // 2,
                    "bytes_read_cumulative": file_read,
                    "bytes_written_cumulative": file_written,
                    "field_operations": field_ops,
                    "challenge": r,
                }
            )
        final_eval = store.read_chunk(0, 1).values[0] if store.len() == 1 else 0
        total_bytes_read = getattr(store, "bytes_read", 0)
        total_bytes_written = getattr(store, "bytes_written", total_bytes_written)
        return {
            "claimed_sum": sum(values) % P,
            "rounds": prefix,
            "final_eval": final_eval,
            "field_ops": total_field_ops,
            "round_metadata": rounds,
            "bytes_read": total_bytes_read,
            "bytes_written": total_bytes_written,
            "complete_table_passes": len(prefix) * 2,
        }
    finally:
        store.cleanup()
