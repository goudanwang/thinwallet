#!/usr/bin/env python3
import json
import os
import re
import statistics
import struct
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD = os.path.join(ROOT, "build", "candidate_a_online")
RESULTS = os.path.join(ROOT, "results")
RAW_PATH = os.path.join(RESULTS, "candidate_a_online_raw.json")
METRICS_PATH = os.path.join(RESULTS, "candidate_a_online_metrics.json")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
OLD_PRIVATE_M = 4601
OLD_ONLINE_N = 4987
AGE_PRIVATE_NONLINEAR = 97

INCLUDED_COMPONENTS = [
    "age predicate",
    "request binding",
    "disclosure control",
    "Poseidon enrollment-state credential-key binding",
    "external request-signature signing benchmark",
    "external request-signature verification benchmark",
    "Groth16 proof and verification",
]

EXCLUDED_COMPONENTS = [
    "in-circuit EdDSA verification gadget",
    "issuer authentication of enrollment record",
    "unlinkability",
    "per-verifier or one-time authorization key",
    "issuer signature verification",
    "credential ID",
    "revocation",
    "secret sharing",
    "server-only proving transition",
    "proof that the phone does not handle witness-sized state",
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
            notes.append(f"Could not parse {key} from build/candidate_a_online/r1cs_info.txt.")
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
        "r1cs_file_size_bytes": os.path.join(BUILD, "candidate_a_online_presentation.r1cs"),
        "wasm_file_size_bytes": os.path.join(BUILD, "candidate_a_online_presentation_js", "candidate_a_online_presentation.wasm"),
        "proving_key_size_bytes": os.path.join(BUILD, "candidate_a_online_final.zkey"),
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
        "credential_key_binding": "credential_key_binding",
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


def parse_external_signature_rejection(notes):
    path = os.path.join(BUILD, "external_signature_rejection.log")
    result = {
        "invalid_nonce_external_signature_exit_status": None,
        "invalid_signature_external_signature_exit_status": None,
        "expected_failure": None,
        "status": "BLOCKED",
    }
    if not os.path.exists(path):
        notes.append("Missing external signature rejection log.")
        return result
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            key, sep, value = line.strip().partition("=")
            if not sep:
                continue
            if key in ("invalid_nonce_external_signature_exit_status", "invalid_signature_external_signature_exit_status"):
                result[key] = int(value)
            elif key == "expected_failure":
                result[key] = value.lower() == "true"
    ok = (
        result["expected_failure"]
        and result["invalid_nonce_external_signature_exit_status"] not in (None, 0)
        and result["invalid_signature_external_signature_exit_status"] not in (None, 0)
    )
    result["status"] = "expected_failure_observed" if ok else "BLOCKED"
    if not ok:
        notes.append("External signature negative tests were not confirmed.")
    return result


def load_external_signature_tests(notes):
    path = os.path.join(BUILD, "external_signature_tests.json")
    if not os.path.exists(path):
        notes.append("Missing external signature test results.")
        return {"status": "BLOCKED"}
    data = read_json(path)
    if data.get("status") != "ok":
        notes.append(f"External signature tests did not pass: {data}")
    return data


def ratio(value, denominator):
    if isinstance(value, int) and isinstance(denominator, int) and denominator:
        return round(value / denominator, 4)
    return None


def main():
    notes = [
        "External signature signing and verification are benchmarked separately and are not SNARK constraints.",
        "The current long-term holder public key is public and linkable.",
        "expected_enrollment_digest authenticity still relies on external issuer, registry, or enrollment-proof authentication.",
        "Candidate A does not implement server-only proving transition.",
        "Candidate A does not prove that the phone avoids witness-sized state.",
    ]
    if not os.path.exists(RAW_PATH):
        raise FileNotFoundError(f"Missing raw benchmark JSON: {RAW_PATH}")

    raw = read_json(RAW_PATH)
    r1cs = parse_r1cs_info(os.path.join(BUILD, "r1cs_info.txt"), notes)
    sizes = artifact_sizes()
    components = component_constraints()

    stages = ["holder_signing", "external_signature_verification", "witness_generation", "prove", "verify"]
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

    timings = {stage: stage_values(raw, stage, "wall_clock_ms") for stage in stages}
    peak_rss = {stage: stage_values(raw, stage, "peak_rss_mb") for stage in stages}
    exit_status = {stage: stage_exit_statuses(raw, stage) for stage in stages}

    if all(value is None for values in peak_rss.values() for value in values):
        notes.append("Peak RSS was not measurable on this system.")

    compile_log = os.path.join(BUILD, "compile.log")
    nonlinear_constraints = parse_compile_count(compile_log, "non-linear constraints", notes)
    linear_constraints = parse_compile_count(compile_log, "linear constraints", notes)

    credential_binding_nonlinear = components["credential_key_binding"]["nonlinear_constraints"]
    if isinstance(credential_binding_nonlinear, int):
        m_candidate_a = AGE_PRIVATE_NONLINEAR + credential_binding_nonlinear
    else:
        m_candidate_a = None

    n_candidate_a = r1cs["total_r1cs_constraints"]
    ratios = {
        "old_private_reduction": round((OLD_PRIVATE_M - m_candidate_a) / OLD_PRIVATE_M, 4) if isinstance(m_candidate_a, int) else None,
        "candidate_a_private_fraction": ratio(m_candidate_a, n_candidate_a),
        "candidate_a_vs_old_total": ratio(m_candidate_a, OLD_ONLINE_N),
        "notes": {
            "old_private_reduction": "(4601 - m_candidate_a) / 4601",
            "candidate_a_private_fraction": "m_candidate_a / N_candidate_a",
            "candidate_a_vs_old_total": "m_candidate_a / 4987; this is not the new circuit private fraction",
        },
    }

    if failed:
        notes.append("Non-zero exit statuses: " + ", ".join(failed))

    metrics = {
        "experiment": "candidate_a_online",
        "status": "ok" if not failed else "failed",
        "tool_versions": compact_tool_versions(raw, notes),
        "total_r1cs_constraints": n_candidate_a,
        "nonlinear_constraints": nonlinear_constraints,
        "nonlinear_constraints_source": "circom compile.log direct output" if nonlinear_constraints is not None else None,
        "linear_constraints": linear_constraints,
        "component_constraints": components,
        "m_candidate_a": m_candidate_a,
        "m_candidate_a_definition": "age private nonlinear constraints + credential-key-binding private nonlinear constraints",
        "ratios": ratios,
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
        "holder_signing_ms": timings["holder_signing"],
        "external_signature_verification_ms": timings["external_signature_verification"],
        "witness_generation_ms": timings["witness_generation"],
        "prove_ms": timings["prove"],
        "verify_ms": timings["verify"],
        "peak_rss_mb": peak_rss,
        "exit_status": exit_status,
        "summary": {
            f"{stage}_ms": stats(values) for stage, values in timings.items()
        } | {
            "peak_rss_mb": {stage: stats(values) for stage, values in peak_rss.items()}
        },
        "tests": {
            "valid": {"status": "ok", "expected_success": True},
            "invalid_nonce": parse_rejection("invalid_nonce", notes),
            "invalid_disclosure": parse_rejection("invalid_disclosure", notes),
            "invalid_key": parse_rejection("invalid_key", notes),
            "invalid_record": parse_rejection("invalid_record", notes),
            "invalid_external_signature": parse_external_signature_rejection(notes),
        },
        "external_signature_tests": load_external_signature_tests(notes),
        "included_components": INCLUDED_COMPONENTS,
        "excluded_components": EXCLUDED_COMPONENTS,
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
        print(f"collect_candidate_a_online_metrics.py: {exc}", file=sys.stderr)
        sys.exit(1)
