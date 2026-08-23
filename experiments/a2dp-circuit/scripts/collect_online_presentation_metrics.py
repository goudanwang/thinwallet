#!/usr/bin/env python3
import json
import os
import re
import statistics
import struct
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD = os.path.join(ROOT, "build", "online_presentation")
RESULTS = os.path.join(ROOT, "results")
RAW_PATH = os.path.join(RESULTS, "online_presentation_raw.json")
METRICS_PATH = os.path.join(RESULTS, "online_presentation_metrics.json")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

INCLUDED_COMPONENTS = [
    "age predicate",
    "request binding",
    "disclosure control",
    "holder authorization",
    "Groth16 proof and verification",
]

EXCLUDED_COMPONENTS = [
    "issuer validity",
    "issuer signature verification",
    "credential binding",
    "credential commitment opening",
    "credential ID",
    "revocation",
    "server-only proving transition",
    "secret sharing",
    "A2DP delegation",
]


def strip_ansi(text):
    return ANSI_RE.sub("", text or "")


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def parse_r1cs_info(path, notes):
    fields = {
        "wires": None,
        "total_r1cs_constraints": None,
        "private_inputs": None,
        "public_inputs": None,
        "outputs": None,
    }
    if not os.path.exists(path):
        notes.append(f"Missing R1CS info file: {os.path.relpath(path, ROOT)}")
        return fields

    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        text = strip_ansi(handle.read())

    patterns = {
        "wires": r"# of Wires:\s*(\d+)",
        "total_r1cs_constraints": r"# of Constraints:\s*(\d+)",
        "private_inputs": r"# of Private Inputs:\s*(\d+)",
        "public_inputs": r"# of Public Inputs:\s*(\d+)",
        "outputs": r"# of Outputs:\s*(\d+)",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text)
        if match:
            fields[key] = int(match.group(1))
        else:
            notes.append(f"Could not parse {key} from build/online_presentation/r1cs_info.txt.")
    return fields


def parse_compile_count(path, label, notes):
    if not os.path.exists(path):
        notes.append(f"Missing compile log; {label} is null.")
        return None
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        text = strip_ansi(handle.read())
    match = re.search(rf"^{re.escape(label)}:\s*(\d+)", text, re.MULTILINE)
    if not match:
        notes.append(f"Could not parse {label} from compile.log.")
        return None
    return int(match.group(1))


def parse_wtns_elements(path, notes):
    if not os.path.exists(path):
        notes.append(f"Missing witness file: {os.path.relpath(path, ROOT)}")
        return None
    try:
        with open(path, "rb") as handle:
            if handle.read(4) != b"wtns":
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
                    return struct.unpack("<I", handle.read(4))[0]
                handle.seek(section_start + section_size)
    except Exception as exc:
        notes.append(f"Could not parse witness element count from .wtns: {exc}")
        return None
    notes.append("Could not find witness header section in .wtns file.")
    return None


def size_or_null(path):
    return os.path.getsize(path) if os.path.exists(path) else None


def artifact_sizes():
    paths = {
        "r1cs_file_size_bytes": os.path.join(BUILD, "online_presentation.r1cs"),
        "wasm_file_size_bytes": os.path.join(BUILD, "online_presentation_js", "online_presentation.wasm"),
        "proving_key_size_bytes": os.path.join(BUILD, "online_presentation_final.zkey"),
        "verification_key_size_bytes": os.path.join(BUILD, "verification_key.json"),
        "proof_size_bytes": os.path.join(BUILD, "valid_proof.json"),
        "public_input_size_bytes": os.path.join(BUILD, "valid_public.json"),
        "witness_file_size_bytes": os.path.join(BUILD, "valid.wtns"),
    }
    return {key: size_or_null(path) for key, path in paths.items()}


def component_metric(name):
    path = os.path.join(RESULTS, f"{name}_metrics.json")
    if not os.path.exists(path):
        return None
    return read_json(path)


def component_constraints():
    mapping = {
        "age_predicate": "age_predicate",
        "request_binding": "request_binding",
        "disclosure_control": "disclosure_control",
        "holder_authorization": "holder_authorization",
    }
    result = {}
    for key, file_stem in mapping.items():
        data = component_metric(file_stem)
        result[key] = {
            "total_r1cs_constraints": data.get("total_r1cs_constraints") if data else None,
            "nonlinear_constraints": data.get("nonlinear_constraints") if data else None,
            "private_inputs": data.get("private_inputs") if data else None,
        }
    return result


def request_dependent_private_m(components):
    age = components["age_predicate"]["nonlinear_constraints"]
    holder = components["holder_authorization"]["nonlinear_constraints"]
    if isinstance(age, int) and isinstance(holder, int):
        return age + holder
    return None


def stage_values(raw, stage, field):
    values = []
    for run in raw.get("stages", {}).get(stage, []):
        value = run.get(field)
        values.append(value if isinstance(value, (int, float)) else None)
    return values


def stats(values):
    numeric = [value for value in values if isinstance(value, (int, float))]
    if len(numeric) != len(values) or not numeric:
        return {"mean": None, "median": None, "min": None, "max": None}
    return {
        "mean": round(statistics.fmean(numeric), 3),
        "median": round(statistics.median(numeric), 3),
        "min": min(numeric),
        "max": max(numeric),
    }


def compact_tool_versions(raw, notes):
    versions = {}
    for name, info in raw.get("tool_versions", {}).items():
        value = info.get("value") if isinstance(info, dict) else None
        versions[name] = value
        if not value:
            notes.append(f"Could not measure tool version for {name}.")
    versions["circomlib"] = "2.0.5"
    versions["curve"] = "BN254 / bn128"
    return versions


def stage_exit_statuses(raw, stage):
    return [run.get("exit_status") for run in raw.get("stages", {}).get(stage, [])]


def parse_rejection(name, notes):
    path = os.path.join(BUILD, f"{name}_rejection.log")
    result = {
        "test": name,
        "witness_exit_status": None,
        "constraint_check_exit_status": None,
        "expected_failure": None,
        "status": "BLOCKED",
    }
    if not os.path.exists(path):
        notes.append(f"Missing rejection log for {name}.")
        return result
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            key, sep, value = line.strip().partition("=")
            if not sep:
                continue
            if key == f"{name}_witness_exit_status":
                result["witness_exit_status"] = int(value)
            elif key == f"{name}_check_exit_status":
                result["constraint_check_exit_status"] = int(value)
            elif key == f"{name}_expected_failure":
                result["expected_failure"] = value.lower() == "true"
    witness_failed = result["witness_exit_status"] not in (None, 0)
    check_failed = result["constraint_check_exit_status"] not in (None, 0)
    if result["expected_failure"] and (witness_failed or check_failed):
        result["status"] = "expected_failure_observed"
    else:
        notes.append(f"Invalid input rejection was not confirmed for {name}.")
    return result


def main():
    notes = []
    if not os.path.exists(RAW_PATH):
        raise FileNotFoundError(f"Missing raw benchmark JSON: {RAW_PATH}")

    raw = read_json(RAW_PATH)
    r1cs = parse_r1cs_info(os.path.join(BUILD, "r1cs_info.txt"), notes)
    sizes = artifact_sizes()
    components = component_constraints()

    failed = []
    for stage in ["witness_generation", "prove", "verify"]:
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

    witness_ms = stage_values(raw, "witness_generation", "wall_clock_ms")
    prove_ms = stage_values(raw, "prove", "wall_clock_ms")
    verify_ms = stage_values(raw, "verify", "wall_clock_ms")
    peak_rss = {
        "witness_generation": stage_values(raw, "witness_generation", "peak_rss_mb"),
        "prove": stage_values(raw, "prove", "peak_rss_mb"),
        "verify": stage_values(raw, "verify", "peak_rss_mb"),
    }
    exit_status = {stage: stage_exit_statuses(raw, stage) for stage in ["witness_generation", "prove", "verify"]}

    if all(value is None for values in peak_rss.values() for value in values):
        notes.append("Peak RSS was not measurable on this system.")

    compile_log = os.path.join(BUILD, "compile.log")
    nonlinear_constraints = parse_compile_count(compile_log, "non-linear constraints", notes)
    linear_constraints = parse_compile_count(compile_log, "linear constraints", notes)

    if failed:
        notes.append("Non-zero exit statuses: " + ", ".join(failed))

    metrics = {
        "experiment": "online_presentation",
        "status": "ok" if not failed else "failed",
        "tool_versions": compact_tool_versions(raw, notes),
        "total_r1cs_constraints": r1cs["total_r1cs_constraints"],
        "nonlinear_constraints": nonlinear_constraints,
        "nonlinear_constraints_source": "circom compile.log direct output" if nonlinear_constraints is not None else None,
        "linear_constraints": linear_constraints,
        "component_constraints": components,
        "request_dependent_private_nonlinear_constraints_m": request_dependent_private_m(components),
        "wires": r1cs["wires"],
        "public_inputs": r1cs["public_inputs"],
        "private_inputs": r1cs["private_inputs"],
        "outputs": r1cs["outputs"],
        "witness_elements": parse_wtns_elements(os.path.join(BUILD, "valid.wtns"), notes),
        "witness_file_size_bytes": sizes["witness_file_size_bytes"],
        "r1cs_file_size_bytes": sizes["r1cs_file_size_bytes"],
        "wasm_file_size_bytes": sizes["wasm_file_size_bytes"],
        "proving_key_size_bytes": sizes["proving_key_size_bytes"],
        "verification_key_size_bytes": sizes["verification_key_size_bytes"],
        "proof_size_bytes": sizes["proof_size_bytes"],
        "public_input_size_bytes": sizes["public_input_size_bytes"],
        "witness_generation_ms": witness_ms,
        "prove_ms": prove_ms,
        "verify_ms": verify_ms,
        "peak_rss_mb": peak_rss,
        "exit_status": exit_status,
        "summary": {
            "witness_generation_ms": stats(witness_ms),
            "prove_ms": stats(prove_ms),
            "verify_ms": stats(verify_ms),
            "peak_rss_mb": {stage: stats(values) for stage, values in peak_rss.items()},
        },
        "negative_tests": {
            "invalid_nonce": parse_rejection("invalid_nonce", notes),
            "invalid_disclosure": parse_rejection("invalid_disclosure", notes),
            "invalid_signature": parse_rejection("invalid_signature", notes),
        },
        "included_components": INCLUDED_COMPONENTS,
        "excluded_components": EXCLUDED_COMPONENTS,
        "notes": notes + [
            "This is not a complete credential presentation cost: issuer validity, credential binding, revocation, and server-only proving transition are not implemented."
        ],
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
        print(f"collect_online_presentation_metrics.py: {exc}", file=sys.stderr)
        sys.exit(1)
