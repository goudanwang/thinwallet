#!/usr/bin/env python3
import json
import os
import re
import struct
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD = os.path.join(ROOT, "build")
RESULTS = os.path.join(ROOT, "results")
RAW_PATH = os.path.join(RESULTS, "sanity_raw.json")
METRICS_PATH = os.path.join(RESULTS, "sanity_metrics.json")


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text):
    return ANSI_RE.sub("", text or "")


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def parse_constraints(path, notes):
    if not os.path.exists(path):
        notes.append(f"Missing R1CS info file: {os.path.relpath(path, ROOT)}")
        return None
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        text = strip_ansi(handle.read())
    match = re.search(r"# of Constraints:\s*(\d+)", text)
    if not match:
        notes.append("Could not parse total constraints from build/r1cs_info.txt.")
        return None
    return int(match.group(1))


def parse_wtns_elements(path, notes):
    if not os.path.exists(path):
        notes.append(f"Missing witness file: {os.path.relpath(path, ROOT)}")
        return None
    try:
        with open(path, "rb") as handle:
            magic = handle.read(4)
            if magic != b"wtns":
                notes.append("Witness file does not start with the expected wtns magic.")
                return None
            _version, section_count = struct.unpack("<II", handle.read(8))
            for _ in range(section_count):
                section_type = struct.unpack("<I", handle.read(4))[0]
                section_size = struct.unpack("<Q", handle.read(8))[0]
                section_start = handle.tell()
                if section_type == 1:
                    n8 = struct.unpack("<I", handle.read(4))[0]
                    handle.seek(n8, os.SEEK_CUR)
                    witness_count = struct.unpack("<I", handle.read(4))[0]
                    return witness_count
                handle.seek(section_start + section_size)
    except Exception as exc:
        notes.append(f"Could not parse witness element count from .wtns: {exc}")
        return None
    notes.append("Could not find witness header section in .wtns file.")
    return None


def artifact_sizes():
    names = [
        "sanity_multiplier.r1cs",
        "sanity_multiplier.sym",
        "sanity_multiplier.wtns",
        os.path.join("sanity_multiplier_js", "generate_witness.js"),
        os.path.join("sanity_multiplier_js", "sanity_multiplier.wasm"),
        os.path.join("sanity_multiplier_js", "witness_calculator.js"),
        "sanity_multiplier_final.zkey",
        "verification_key.json",
        "proof.json",
        "public.json",
        "verify.log",
        "r1cs_info.txt",
    ]
    sizes = {}
    for name in names:
        path = os.path.join(BUILD, name)
        sizes[name.replace(os.sep, "/")] = os.path.getsize(path) if os.path.exists(path) else None
    return sizes


def stage_values(raw, stage, field):
    values = []
    for run in raw.get("stages", {}).get(stage, []):
        value = run.get(field)
        values.append(value if isinstance(value, (int, float)) else None)
    return values


def stage_exit_statuses(raw, stage):
    return [run.get("exit_status") for run in raw.get("stages", {}).get(stage, [])]


def compact_tool_versions(raw, notes):
    versions = {}
    for name, info in raw.get("tool_versions", {}).items():
        value = info.get("value") if isinstance(info, dict) else None
        versions[name] = value
        if not value:
            notes.append(f"Could not measure tool version for {name}.")
    return versions


def main():
    notes = []
    if not os.path.exists(RAW_PATH):
        raise FileNotFoundError(f"Missing raw benchmark JSON: {RAW_PATH}")

    raw = read_json(RAW_PATH)
    stages = ["witness_generation", "prove", "verify"]

    failed = []
    for stage in stages:
        statuses = stage_exit_statuses(raw, stage)
        if len(statuses) != raw.get("runs_per_stage"):
            notes.append(f"Stage {stage} has {len(statuses)} recorded runs.")
        failed.extend(f"{stage}[{idx + 1}]={status}" for idx, status in enumerate(statuses) if status != 0)

    verify_outputs = [
        strip_ansi((run.get("stdout") or "") + "\n" + (run.get("stderr") or ""))
        for run in raw.get("stages", {}).get("verify", [])
    ]
    if verify_outputs and not all("OK" in output for output in verify_outputs):
        notes.append("At least one verification run did not print OK.")

    peak_rss = {stage: stage_values(raw, stage, "peak_rss_mb") for stage in stages}
    if all(value is None for values in peak_rss.values() for value in values):
        notes.append("Peak RSS was not measurable on this system.")

    if failed:
        notes.append("Non-zero exit statuses: " + ", ".join(failed))

    metrics = {
        "experiment": "sanity_multiplier",
        "status": "ok" if not failed else "failed",
        "tool_versions": compact_tool_versions(raw, notes),
        "total_constraints": parse_constraints(os.path.join(BUILD, "r1cs_info.txt"), notes),
        "witness_elements": parse_wtns_elements(os.path.join(BUILD, "sanity_multiplier.wtns"), notes),
        "artifact_sizes_bytes": artifact_sizes(),
        "witness_generation_ms": stage_values(raw, "witness_generation", "wall_clock_ms"),
        "prove_ms": stage_values(raw, "prove", "wall_clock_ms"),
        "verify_ms": stage_values(raw, "verify", "wall_clock_ms"),
        "peak_rss_mb": peak_rss,
        "notes": notes,
    }

    os.makedirs(RESULTS, exist_ok=True)
    with open(METRICS_PATH, "w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)
        handle.write("\n")

    print(os.path.relpath(METRICS_PATH, ROOT))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"collect_sanity_metrics.py: {exc}", file=sys.stderr)
        sys.exit(1)
