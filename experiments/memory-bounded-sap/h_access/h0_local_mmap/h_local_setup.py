from __future__ import annotations

import time
from pathlib import Path

from emsm_real.remote_h import compute_h_vector
from emsm_real.server_streaming_msm import make_basis
from h_access.h0_local_mmap.h_file_format import write_h_file


def generate_h_file(params, path: Path) -> dict[str, object]:
    start = time.perf_counter()
    basis = make_basis(params.input_len_n, params.emsm.parameter_version)
    h = compute_h_vector(params, basis)
    manifest = write_h_file(
        path,
        h,
        {
            "backend_id": "INTERNAL_FFT_FREE_MULTILINEAR_SUMCHECK_PHASE1_BACKEND",
            "curve_id": params.emsm.curve_id,
            "field_id": params.emsm.field_id,
            "parameter_version": params.emsm.parameter_version,
            "n": params.input_len_n,
            "N": params.code_len_N,
            "endian": "little",
            "format_version": "phase2b-h0-v1",
        },
    )
    elapsed = (time.perf_counter() - start) * 1000
    return {
        "manifest": manifest.__dict__,
        "one_time_installation_time_ms": elapsed,
        "complete_h_file_bytes": path.stat().st_size,
        "manifest_bytes": len(str(manifest.__dict__).encode("utf-8")),
    }

