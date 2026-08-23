from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from common import FIELD_BYTES
from h_access.common.interfaces import ParameterManifest

MAGIC = b"H0HFILE1"
HEADER_FIXED = 16


def _header_bytes(header: dict[str, object]) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_h_file(path: Path, values: list[int], header: dict[str, object]) -> ParameterManifest:
    header = dict(header)
    header["element_byte_len"] = FIELD_BYTES
    body_hasher = hashlib.sha256()
    tmp = path.with_suffix(path.suffix + ".tmp")
    for value in values:
        body_hasher.update(int(value).to_bytes(FIELD_BYTES, "little"))
    root_digest = body_hasher.hexdigest()
    header["root_digest"] = root_digest
    header["complete_file_digest"] = root_digest
    hbytes = _header_bytes(header)
    with tmp.open("wb") as fh:
        fh.write(MAGIC)
        fh.write(struct.pack("<Q", len(hbytes)))
        fh.write(hbytes)
        for value in values:
            fh.write(int(value).to_bytes(FIELD_BYTES, "little"))
    tmp.replace(path)
    return read_manifest(path)


def read_header(path: Path) -> tuple[dict[str, object], int]:
    with path.open("rb") as fh:
        magic = fh.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("wrong h file magic")
        header_len = struct.unpack("<Q", fh.read(8))[0]
        header = json.loads(fh.read(header_len).decode("utf-8"))
        return header, len(MAGIC) + 8 + header_len


def read_manifest(path: Path) -> ParameterManifest:
    header, _ = read_header(path)
    return ParameterManifest(
        backend_id=str(header["backend_id"]),
        curve_id=str(header["curve_id"]),
        field_id=str(header["field_id"]),
        parameter_version=str(header["parameter_version"]),
        n=int(header["n"]),
        N=int(header["N"]),
        element_byte_len=int(header["element_byte_len"]),
        root_digest=str(header["root_digest"]),
        complete_file_digest=str(header["complete_file_digest"]),
    )
