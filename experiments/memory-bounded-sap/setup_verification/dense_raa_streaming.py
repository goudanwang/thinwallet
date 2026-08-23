from __future__ import annotations

from common import P
from emsm_real.raa_encoder_streaming import StreamingRaaMetrics
from emsm_real.raa_external_store import ExternalFieldStore, read_field, write_field
from emsm_real.raa_parameters import RaaParameters
from setup_verification.challenge import alpha_i
from setup_verification.dense_raa_reference import dense_reference_g_alpha


def _write_alpha(params: RaaParameters, manifest_digest: str, nonce: str, check_round: int, store: ExternalFieldStore) -> str:
    path = store.path("00_alpha.bin")
    with path.open("wb") as fh:
        for i in range(params.code_len_N):
            write_field(fh, alpha_i(manifest_digest, nonce, check_round, i))
    store.bytes_written += params.code_len_N * 32
    return str(path)


def _accumulate(params: RaaParameters, in_path: str, name: str, store: ExternalFieldStore, metrics: StreamingRaaMetrics) -> str:
    out = store.path(name)
    acc = 0
    with open(in_path, "rb") as src, out.open("wb") as dst:
        for _ in range(params.code_len_N):
            acc = (acc + read_field(src)) % P
            write_field(dst, acc)
            metrics.field_additions += 1
    metrics.bytes_read += params.code_len_N * 32
    metrics.bytes_written += params.code_len_N * 32
    metrics.sequential_reads += params.code_len_N
    metrics.number_of_passes += 1
    return str(out)


def _permute(params: RaaParameters, in_path: str, name: str, a: int, b: int, store: ExternalFieldStore, metrics: StreamingRaaMetrics) -> str:
    out = store.path(name)
    N = params.code_len_N
    with open(in_path, "rb") as src, out.open("wb") as dst:
        for _ in range(N):
            write_field(dst, 0)
        for i in range(N):
            src.seek(i * 32)
            value = read_field(src)
            dst.seek(((a * i + b) % N) * 32)
            write_field(dst, value)
    metrics.bytes_read += N * 32
    metrics.bytes_written += N * 32
    metrics.random_reads += N
    metrics.number_of_passes += 1
    return str(out)


def _fold(params: RaaParameters, in_path: str, name: str, store: ExternalFieldStore, metrics: StreamingRaaMetrics) -> str:
    out = store.path(name)
    with open(in_path, "rb") as src, out.open("wb") as dst:
        for _ in range(params.input_len_n):
            acc = 0
            for _ in range(params.repetition):
                acc = (acc + read_field(src)) % P
                metrics.field_additions += 1
            write_field(dst, acc)
    metrics.bytes_read += params.code_len_N * 32
    metrics.bytes_written += params.input_len_n * 32
    metrics.sequential_reads += params.code_len_N
    metrics.number_of_passes += 1
    return str(out)


def dense_streaming_g_alpha(params: RaaParameters, manifest_digest: str, nonce: str, check_round: int) -> tuple[list[int], dict[str, object]]:
    store = ExternalFieldStore()
    metrics = StreamingRaaMetrics()
    try:
        p0 = _write_alpha(params, manifest_digest, nonce, check_round, store)
        p1 = _accumulate(params, p0, "01_acc.bin", store, metrics)
        p2 = _permute(params, p1, "02_sigma2.bin", params.sigma2_a, params.sigma2_b, store, metrics)
        p3 = _accumulate(params, p2, "03_acc.bin", store, metrics)
        p4 = _permute(params, p3, "04_sigma1.bin", params.sigma1_a, params.sigma1_b, store, metrics)
        out_path = _fold(params, p4, "05_beta.bin", store, metrics)
        beta: list[int] = []
        with open(out_path, "rb") as fh:
            for _ in range(params.input_len_n):
                beta.append(read_field(fh))
        metrics.bytes_read += params.input_len_n * 32
        metrics.temporary_storage = store.temporary_storage_bytes
        return beta, metrics.to_json()
    finally:
        store.cleanup()


def dense_compare(params: RaaParameters, manifest_digest: str, nonce: str, check_round: int) -> dict[str, object]:
    alpha = [alpha_i(manifest_digest, nonce, check_round, i) for i in range(params.code_len_N)]
    ref = dense_reference_g_alpha(params, alpha)
    got, metrics = dense_streaming_g_alpha(params, manifest_digest, nonce, check_round)
    return {"ok": ref == got, "metrics": metrics}

