from __future__ import annotations

from dataclasses import dataclass

from common import FIELD_BYTES, P
from emsm_real.raa_encoder_reference import reference_encode
from emsm_real.raa_external_store import ExternalFieldStore, read_field, write_field
from emsm_real.raa_parameters import RaaParameters
from emsm_real.sparse_noise import SparseNoise, validate_sparse_noise


@dataclass
class StreamingRaaMetrics:
    bytes_read: int = 0
    bytes_written: int = 0
    number_of_passes: int = 0
    field_additions: int = 0
    random_reads: int = 0
    sequential_reads: int = 0
    temporary_storage: int = 0
    peak_RSS_MB: float | None = None

    def to_json(self) -> dict[str, object]:
        return self.__dict__.copy()


class StreamingRaaEncoder:
    def __init__(self, params: RaaParameters, sparse: SparseNoise, chunk_size: int) -> None:
        validate_sparse_noise(params, sparse)
        self.params = params
        self.sparse = sparse
        self.chunk_size = chunk_size
        self.offset = 0
        self.metrics = StreamingRaaMetrics()
        self._store = ExternalFieldStore()
        self._output_path = self._encode_to_external_store()

    @classmethod
    def begin(cls, params: RaaParameters, sparse_noise: SparseNoise, chunk_size: int) -> "StreamingRaaEncoder":
        return cls(params, sparse_noise, chunk_size)

    def _write_sparse(self, path_name: str) -> str:
        entries = dict(self.sparse.entries)
        path = self._store.path(path_name)
        with path.open("wb") as fh:
            for i in range(self.params.code_len_N):
                write_field(fh, entries.get(i, 0))
        self.metrics.bytes_written += self.params.code_len_N * FIELD_BYTES
        self.metrics.number_of_passes += 1
        return str(path)

    def _accumulate(self, in_path: str, out_name: str) -> str:
        out_path = self._store.path(out_name)
        acc = 0
        with open(in_path, "rb") as src, out_path.open("wb") as dst:
            for _ in range(self.params.code_len_N):
                value = read_field(src)
                acc = (acc + value) % P
                write_field(dst, acc)
                self.metrics.field_additions += 1
        self.metrics.bytes_read += self.params.code_len_N * FIELD_BYTES
        self.metrics.bytes_written += self.params.code_len_N * FIELD_BYTES
        self.metrics.sequential_reads += self.params.code_len_N
        self.metrics.number_of_passes += 1
        return str(out_path)

    def _permute(self, in_path: str, out_name: str, a: int, b: int) -> str:
        out_path = self._store.path(out_name)
        N = self.params.code_len_N
        with open(in_path, "rb") as src, out_path.open("wb") as dst:
            for _ in range(N):
                write_field(dst, 0)
            for i in range(N):
                src.seek(i * FIELD_BYTES)
                value = read_field(src)
                out_idx = (a * i + b) % N
                dst.seek(out_idx * FIELD_BYTES)
                write_field(dst, value)
        self.metrics.bytes_read += N * FIELD_BYTES
        self.metrics.bytes_written += N * FIELD_BYTES
        self.metrics.random_reads += N
        self.metrics.number_of_passes += 1
        return str(out_path)

    def _fold(self, in_path: str, out_name: str) -> str:
        out_path = self._store.path(out_name)
        with open(in_path, "rb") as src, out_path.open("wb") as dst:
            for _ in range(self.params.input_len_n):
                acc = 0
                for _ in range(self.params.repetition):
                    acc = (acc + read_field(src)) % P
                    self.metrics.field_additions += 1
                write_field(dst, acc)
        self.metrics.bytes_read += self.params.code_len_N * FIELD_BYTES
        self.metrics.bytes_written += self.params.input_len_n * FIELD_BYTES
        self.metrics.sequential_reads += self.params.code_len_N
        self.metrics.number_of_passes += 1
        return str(out_path)

    def _encode_to_external_store(self) -> str:
        p0 = self._write_sparse("00_sparse.bin")
        p1 = self._accumulate(p0, "01_acc.bin")
        p2 = self._permute(p1, "02_sigma2.bin", self.params.sigma2_a, self.params.sigma2_b)
        p3 = self._accumulate(p2, "03_acc.bin")
        p4 = self._permute(p3, "04_sigma1.bin", self.params.sigma1_a, self.params.sigma1_b)
        out = self._fold(p4, "05_mask.bin")
        self.metrics.temporary_storage = self._store.temporary_storage_bytes
        return out

    def next_mask_chunk(self) -> tuple[int, list[int]] | None:
        if self.offset >= self.params.input_len_n:
            return None
        length = min(self.chunk_size, self.params.input_len_n - self.offset)
        values: list[int] = []
        with open(self._output_path, "rb") as fh:
            fh.seek(self.offset * FIELD_BYTES)
            for _ in range(length):
                values.append(read_field(fh))
        start = self.offset
        self.offset += length
        self.metrics.bytes_read += length * FIELD_BYTES
        self.metrics.sequential_reads += length
        return start, values

    def cleanup(self) -> None:
        self._store.cleanup()


def compare_streaming_to_reference(params: RaaParameters, sparse: SparseNoise, chunk_size: int) -> dict[str, object]:
    ref = reference_encode(params, sparse)
    enc = StreamingRaaEncoder.begin(params, sparse, chunk_size)
    got: list[int] = []
    try:
        while True:
            chunk = enc.next_mask_chunk()
            if chunk is None:
                break
            offset, values = chunk
            if offset != len(got):
                raise ValueError("non-deterministic output offset")
            got.extend(values)
        return {"ok": got == ref, "metrics": enc.metrics.to_json()}
    finally:
        enc.cleanup()

