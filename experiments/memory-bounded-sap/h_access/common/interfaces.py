from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ParameterManifest:
    backend_id: str
    curve_id: str
    field_id: str
    parameter_version: str
    n: int
    N: int
    element_byte_len: int
    root_digest: str
    complete_file_digest: str


@dataclass(frozen=True)
class AuthenticatedHEntry:
    index: int
    compressed_group_element: bytes
    parameter_version: str
    vector_length: int
    curve_id: str
    authentication_data: dict[str, object]


class HEntryProvider:
    def begin_session(self, manifest: ParameterManifest, request_digest: bytes) -> None:
        raise NotImplementedError

    def fetch_entries(self, indices: list[int]) -> list[AuthenticatedHEntry]:
        raise NotImplementedError

    def finish_session(self) -> None:
        raise NotImplementedError

