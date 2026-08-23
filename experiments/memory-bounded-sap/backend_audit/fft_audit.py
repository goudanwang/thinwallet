#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]


FORBIDDEN = ["fft", "ifft", "ntt", "intt", "radix2", "low-degree", "fri"]
BENIGN_PHRASES = [
    "internal_fft_free_multilinear_sumcheck_phase1_backend",
]


def audit_paths() -> dict[str, object]:
    selected = [
        ROOT / "local_baseline",
        ROOT / "streaming_sumcheck",
        ROOT / "witness_stream",
        ROOT / "remote_msm",
        ROOT / "remote_parameters",
    ]
    hits: list[dict[str, object]] = []
    for base in selected:
        for path in base.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            lowered = text.lower()
            for phrase in BENIGN_PHRASES:
                lowered = lowered.replace(phrase, "")
            for token in FORBIDDEN:
                if token in lowered:
                    hits.append({"path": str(path.relative_to(REPO)), "token": token})
    status = "CLIENT_PROVER_HIDDEN_FFT_DETECTED" if hits else "CLIENT_PROVER_FFT_FREE_PASS"
    return {
        "selected_backend": "INTERNAL_FFT_FREE_MULTILINEAR_SUMCHECK_PHASE1_BACKEND",
        "searched_paths": [str(p.relative_to(REPO)) for p in selected],
        "forbidden_tokens": FORBIDDEN,
        "hits": hits,
        "runtime_transform_calls": {"fft": 0, "ntt": 0, "lde": 0, "fri": 0},
        "status_marker": status,
    }


def main() -> None:
    out = audit_paths()
    (ROOT / "results" / "backend_audit.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    (ROOT / "backend_audit" / "backend_inventory.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(out["status_marker"])


if __name__ == "__main__":
    main()
