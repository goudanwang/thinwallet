from __future__ import annotations

from pathlib import Path

from common import FIELD_BYTES, P
from h_access.h0_local_mmap.h_file_format import read_header
from setup_verification.challenge import alpha_i
from setup_verification.dense_raa_streaming import dense_streaming_g_alpha


def stream_h_alpha_sum(h_path: Path, manifest_digest: str, nonce: str, check_round: int) -> tuple[int, dict[str, object]]:
    header, body_offset = read_header(h_path)
    N = int(header["N"])
    acc = 0
    field_ops = 0
    with h_path.open("rb") as fh:
        fh.seek(body_offset)
        for i in range(N):
            data = fh.read(FIELD_BYTES)
            if len(data) != FIELD_BYTES:
                raise ValueError("truncated h file")
            h_i = int.from_bytes(data, "little") % P
            a_i = alpha_i(manifest_digest, nonce, check_round, i)
            acc = (acc + a_i * h_i) % P
            field_ops += 2
    return acc, {"group_operations_model": N, "field_operations": field_ops, "bytes_read": N * FIELD_BYTES}


def stream_g_beta_sum(basis: list[int], beta: list[int]) -> tuple[int, dict[str, object]]:
    if len(basis) != len(beta):
        raise ValueError("beta length mismatch")
    acc = 0
    for b, g in zip(beta, basis):
        acc = (acc + b * g) % P
    return acc, {"group_operations_model": len(beta), "field_operations": 2 * len(beta), "bytes_read": len(beta) * FIELD_BYTES}


def v2_random_linear_check(params, h_path: Path, basis: list[int], manifest_digest: str, nonce: str, rounds: int) -> dict[str, object]:
    round_results = []
    for r in range(rounds):
        beta, beta_metrics = dense_streaming_g_alpha(params, manifest_digest, nonce, r)
        left, left_metrics = stream_h_alpha_sum(h_path, manifest_digest, nonce, r)
        right, right_metrics = stream_g_beta_sum(basis, beta)
        round_results.append(
            {
                "round": r,
                "accepted": left == right,
                "left_metrics": left_metrics,
                "right_metrics": right_metrics,
                "dense_raa_metrics": beta_metrics,
            }
        )
    return {
        "status_marker": "V2_RANDOM_LINEAR_SETUP_CHECK_PASS" if all(x["accepted"] for x in round_results) else "V2_RANDOM_LINEAR_SETUP_CHECK_FAIL",
        "rounds": rounds,
        "soundness_error_per_round": "at most 1/|F|",
        "round_results": round_results,
    }

