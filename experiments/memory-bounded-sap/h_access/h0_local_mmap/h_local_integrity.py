from __future__ import annotations

import hashlib
from pathlib import Path

from h_access.h0_local_mmap.h_file_format import read_header


def verify_h_file(path: Path) -> dict[str, object]:
    header, body_offset = read_header(path)
    body = path.read_bytes()[body_offset:]
    body_digest = hashlib.sha256(body).hexdigest()
    if body_digest != header.get("root_digest"):
        raise ValueError("h root digest mismatch")
    if body_digest != header.get("complete_file_digest"):
        raise ValueError("complete h body digest mismatch")
    return {
        "status_marker": "H0_PARAMETER_INSTALLATION_PASS",
        "complete_file_digest": body_digest,
        "root_digest": body_digest,
        "verified_bytes": path.stat().st_size,
    }
