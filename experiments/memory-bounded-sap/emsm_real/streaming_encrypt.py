from __future__ import annotations

from common import P
from emsm_real.ciphertext_stream import CiphertextChunk, CiphertextStream
from emsm_real.client_secret_state import ClientSecretState
from emsm_real.raa_encoder_streaming import StreamingRaaEncoder
from emsm_real.raa_parameters import RaaParameters


def streaming_encrypt(
    params: RaaParameters,
    z_values: list[int],
    encoder: StreamingRaaEncoder,
    secret_state: ClientSecretState,
    chunk_size: int,
    session_id: str,
    request_digest: str,
) -> tuple[CiphertextStream, dict[str, object]]:
    if len(z_values) != params.input_len_n:
        raise ValueError("wrong witness vector length")
    if secret_state.sparse_noise.session_id != session_id:
        raise ValueError("session binding mismatch")
    secret_state.mark_used()
    stream = CiphertextStream(params.input_len_n, session_id, request_digest)
    zeroized_chunks = 0
    while True:
        mask_chunk = encoder.next_mask_chunk()
        if mask_chunk is None:
            break
        offset, r_chunk = mask_chunk
        z_chunk = [v % P for v in z_values[offset : offset + len(r_chunk)]]
        v_chunk = [(a + b) % P for a, b in zip(z_chunk, r_chunk)]
        stream.append(CiphertextChunk(offset, v_chunk))
        for i in range(len(z_chunk)):
            z_chunk[i] = 0
            r_chunk[i] = 0
            v_chunk[i] = 0
        zeroized_chunks += 1
    secret_state.clear()
    return stream, {
        "status_marker": "STREAMING_EMSM_ENCRYPT_PASS",
        "zeroized_chunks": zeroized_chunks,
        "request_digest": request_digest,
        "session_id": session_id,
    }

