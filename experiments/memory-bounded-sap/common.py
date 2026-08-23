#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
import tracemalloc
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
FIELD_BYTES = 32


def fr(value: int) -> int:
    return value % P


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def hash_to_field(*parts: Any) -> int:
    h = hashlib.sha256()
    for part in parts:
        h.update(stable_json(part).encode("utf-8"))
        h.update(b"|")
    return int.from_bytes(h.digest(), "big") % P


def witness_prf(seed: int, index: int, domain: str) -> int:
    return hash_to_field("WitnessPRF", seed, index, domain)


def now_ms() -> float:
    return time.perf_counter() * 1000.0


def mean_median_p95(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"mean": None, "median": None, "p95": None}
    ordered = sorted(values)
    idx = min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1)
    return {
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "p95": ordered[idx],
    }


def git_commit(root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return proc.stdout.strip() or None if proc.returncode == 0 else None
    except OSError:
        return None


def current_rss_mb() -> float | None:
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(counters)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            ok = ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
            if ok:
                return counters.WorkingSetSize / (1024 * 1024)
        except Exception:
            return None
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "darwin":
            return usage / (1024 * 1024)
        return usage / 1024
    except Exception:
        return None
    return None


@contextmanager
def measured_block() -> Iterator[dict[str, float | None]]:
    rss_start = current_rss_mb()
    tracemalloc.start()
    start = now_ms()
    record: dict[str, float | None] = {}
    try:
        yield record
    finally:
        elapsed = now_ms() - start
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rss_end = current_rss_mb()
        record.update(
            {
                "wall_time_ms": elapsed,
                "rss_start_mb": rss_start,
                "rss_end_mb": rss_end,
                "peak_rss_mb": max([x for x in (rss_start, rss_end) if x is not None], default=None),
                "peak_python_alloc_mb": peak / (1024 * 1024),
            }
        )


def env_record(root: Path) -> dict[str, Any]:
    return {
        "git_commit": git_commit(root),
        "backend_version": "internal-fft-free-multilinear-sumcheck-phase1",
        "compiler_version": sys.version.split()[0],
        "cpu": platform.processor() or platform.machine(),
        "ram": None,
        "os": platform.platform(),
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


@dataclass
class FieldChunk:
    offset: int
    values: list[int]

    def checksum(self) -> str:
        return digest({"offset": self.offset, "values": self.values})
