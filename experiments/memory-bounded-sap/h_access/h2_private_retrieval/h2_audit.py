from __future__ import annotations

import json
import subprocess
from pathlib import Path


def audit_h2(root: Path) -> dict[str, object]:
    candidates = [
        {
            "scheme": "chalametpir_client/server/common",
            "security_assumption": "library-specific single-server PIR assumption; not audited in this repository",
            "client_query_size": None,
            "server_work": None,
            "response_size": None,
            "client_memory": None,
            "preprocessing": "stateful key-value PIR according to crate summary",
            "batch_query_support": "unknown from cargo search summary",
            "authentication_support": "not established",
            "implementation_maturity": "available on crates.io, not vendored or integrated",
            "license": None,
            "selected": False,
            "reason": "not an audited local dependency; arbitrary fixed h-record authentication and batch integration not verified",
        },
        {
            "scheme": "inspire",
            "security_assumption": "communication-efficient PIR with server-side preprocessing; details not audited locally",
            "client_query_size": None,
            "server_work": None,
            "response_size": None,
            "client_memory": None,
            "preprocessing": "server-side preprocessing",
            "batch_query_support": "unknown from cargo search summary",
            "authentication_support": "not established",
            "implementation_maturity": "available on crates.io, not vendored or integrated",
            "license": None,
            "selected": False,
            "reason": "not an audited local dependency; integration/security review missing",
        },
        {
            "scheme": "pir / pir-client",
            "security_assumption": "crate-specific; not audited locally",
            "client_query_size": None,
            "server_work": None,
            "response_size": None,
            "client_memory": None,
            "preprocessing": "unknown",
            "batch_query_support": "unknown",
            "authentication_support": "not established",
            "implementation_maturity": "available on crates.io search, not integrated",
            "license": None,
            "selected": False,
            "reason": "insufficient local audit for Phase 2B H2 implementation",
        },
        {
            "scheme": "spiral/sealpir-style single-server PIR",
            "security_assumption": "RLWE/LWE depending library",
            "client_query_size": None,
            "server_work": None,
            "response_size": None,
            "client_memory": None,
            "preprocessing": "public database preprocessing likely required",
            "batch_query_support": "library-dependent",
            "authentication_support": "usually separate",
            "implementation_maturity": "no dependency found in repository",
            "license": None,
            "selected": False,
            "reason": "not present as an auditable local dependency",
        },
        {
            "scheme": "plain encrypted indices",
            "security_assumption": "none for single-server query privacy",
            "selected": False,
            "reason": "rejected: not PIR and reveals access pattern to the server performing lookup",
        },
    ]
    return {
        "status_marker": "H2_NO_AUDITABLE_PIR_LIBRARY_FOUND",
        "measurement_type": "NOT_IMPLEMENTED",
        "searched": [
            "repository Cargo dependencies",
            "existing experiments",
            "local references",
            "cargo search pir --limit 20",
            "cargo search 'single server PIR' --limit 10",
        ],
        "candidates": candidates,
        "notes": [
            "No single-server PIR dependency with auditable Rust integration was found locally.",
            "H2 implementation is stopped as required; no homemade PIR is substituted.",
        ],
    }
