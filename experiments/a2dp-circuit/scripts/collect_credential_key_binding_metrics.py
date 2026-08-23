#!/usr/bin/env python3
import json
import os
import re
import statistics
import struct
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD = os.path.join(ROOT, "build", "credential_key_binding")
RESULTS = os.path.join(ROOT, "results")
RAW_PATH = os.path.join(RESULTS, "credential_key_binding_raw.json")
METRICS_PATH = os.path.join(RESULTS, "credential_key_binding_metrics.json")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
OLD_HOLDER_AUTH_CONSTRAINTS = 4504
AGE_PRIVATE_NONLINEAR = 97
OLD_PRIVATE_NONLINEAR_M = 4601
ONLINE_PRESENTATION_CONSTRAINTS_N = 4987

INCLUDED_COMPONENTS = [
    "Poseidon enrollment-state binding",
    "holder public key substitution resistance under authenticated-record assumption",
    "external request-signature verification benchmark",
    "Groth16 proof and verification for the credential-key binding circuit",
]

EXCLUDED_COMPONENTS = [
    "issuer authentication of enrollment record",
    "unlinkability",
    "per-verifier or one-time authorization key",
    "issuer signature verification",
    "revocation",
    "secret sharing",
    "server-only proving transition",
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
            notes.append(f"Could not parse {key} from build/credential_key_binding/r1cs_info.txt.")
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
        "r1cs_file_size_bytes": os.path.join(BUILD, "credential_key_binding_main.r1cs"),
        "wasm_file_size_bytes": os.path.join(BUILD, "credential_key_binding_main_js", "credential_key_binding_main.wasm"),
        "proving_key_size_bytes": os.path.join(BUILD, "credential_key_binding_final.zkey"),
        "verification_key_size_bytes": os.path.join(BUILD, "verification_key.json"),
        "proof_size_bytes": os.path.join(BUILD, "valid_proof.json"),
        "public_input_size_bytes": os.path.join(BUILD, "valid_public.json"),
        "witness_file_size_bytes": os.path.join(BUILD, "valid.wtns"),
    }
    return {key: size_or_null(path) for key, path in paths.items()}


def stage_values(raw, stage, field):
    values = []
    for run in raw.get("stages", {}).get(stage, []):
        value = run.get(field)
        values.append(value if isinstance(value, (int, float)) else None)
    return values


def stats(values):
    numeric = [value for value in values if isinstance(value, (int, float))]
    if len(numeric) != len(values) or not numeric:
        return {
            "mean": None,
            "median": None,
            "min": None,
            "max": None,
        }
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
    versions["circomlibjs"] = "0.1.7"
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


def load_external_signature_tests(notes):
    path = os.path.join(BUILD, "external_signature_tests.json")
    if not os.path.exists(path):
        notes.append("Missing external signature test results.")
        return {
            "valid_signature_verifies": None,
            "modified_request_old_signature_verifies": None,
            "wrong_signature_verifies": None,
            "status": "BLOCKED",
        }
    data = read_json(path)
    if data.get("status") != "ok":
        notes.append(f"External signature tests did not pass: {data}")
    return data


def main():
    notes = [
        "expected_enrollment_digest is assumed to be authenticated by an issuer, registry, or prior enrollment proof.",
        "Without authenticated enrollment records, a server could register its own holder public key.",
        "The public long-term holder public key is linkable; this is a linkable baseline, not the final design.",
        "External signature verification is benchmarked separately and is not included in R1CS constraints.",
    ]
    if not os.path.exists(RAW_PATH):
        raise FileNotFoundError(f"Missing raw benchmark JSON: {RAW_PATH}")

    raw = read_json(RAW_PATH)
    r1cs = parse_r1cs_info(os.path.join(BUILD, "r1cs_info.txt"), notes)
    sizes = artifact_sizes()

    stages = ["witness_generation", "prove", "verify", "external_signature_verification"]
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

    witness_ms = stage_values(raw, "witness_generation", "wall_clock_ms")
    prove_ms = stage_values(raw, "prove", "wall_clock_ms")
    verify_ms = stage_values(raw, "verify", "wall_clock_ms")
    external_sig_ms = stage_values(raw, "external_signature_verification", "wall_clock_ms")
    peak_rss = {
        "witness_generation": stage_values(raw, "witness_generation", "peak_rss_mb"),
        "prove": stage_values(raw, "prove", "peak_rss_mb"),
        "verify": stage_values(raw, "verify", "peak_rss_mb"),
        "external_signature_verification": stage_values(raw, "external_signature_verification", "peak_rss_mb"),
    }
    exit_status = {stage: stage_exit_statuses(raw, stage) for stage in stages}

    if all(value is None for values in peak_rss.values() for value in values):
        notes.append("Peak RSS was not measurable on this system.")

    compile_log = os.path.join(BUILD, "compile.log")
    nonlinear_constraints = parse_compile_count(compile_log, "non-linear constraints", notes)
    linear_constraints = parse_compile_count(compile_log, "linear constraints", notes)

    if failed:
        notes.append("Non-zero exit statuses: " + ", ".join(failed))

    if nonlinear_constraints is None:
        m_candidate_a = None
        m_candidate_a_ratio = None
        holder_auth_constraint_reduction = None
        private_cost_reduction_from_old_m = None
    else:
        m_candidate_a = nonlinear_constraints + AGE_PRIVATE_NONLINEAR
        m_candidate_a_ratio = round(m_candidate_a / ONLINE_PRESENTATION_CONSTRAINTS_N, 4)
        holder_auth_constraint_reduction = OLD_HOLDER_AUTH_CONSTRAINTS - nonlinear_constraints
        private_cost_reduction_from_old_m = OLD_PRIVATE_NONLINEAR_M - m_candidate_a

    metrics = {
        "experiment": "credential_key_binding",
        "status": "ok" if not failed else "failed",
        "tool_versions": compact_tool_versions(raw, notes),
        "total_r1cs_constraints": r1cs["total_r1cs_constraints"],
        "nonlinear_constraints": nonlinear_constraints,
        "nonlinear_constraints_source": "circom compile.log direct output" if nonlinear_constraints is not None else None,
        "linear_constraints": linear_constraints,
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
        "external_signature_verification_ms": external_sig_ms,
        "peak_rss_mb": peak_rss,
        "exit_status": exit_status,
        "summary": {
            "witness_generation_ms": stats(witness_ms),
            "prove_ms": stats(prove_ms),
            "verify_ms": stats(verify_ms),
            "external_signature_verification_ms": stats(external_sig_ms),
            "peak_rss_mb": {stage: stats(values) for stage, values in peak_rss.items()},
        },
        "constraint_breakdown": {
            "Poseidon_5_enrollment_digest": {
                "inputs": [
                    "credential_commitment",
                    "holder_public_key_x",
                    "holder_public_key_y",
                    "issuer_id",
                    "schema_id",
                ],
                "nonlinear_constraints": nonlinear_constraints,
            },
            "digest_equality": {
                "constraints": linear_constraints,
                "type": "linear",
            },
            "notes": [
                "The circuit does not include an EdDSA verification gadget.",
                "The binding cost is the compiled Poseidon enrollment digest plus digest equality.",
            ],
        },
        "old_private_cost": {
            "holder_authorization_constraints": OLD_HOLDER_AUTH_CONSTRAINTS,
            "age_predicate_private_nonlinear_constraints": AGE_PRIVATE_NONLINEAR,
            "m_old": OLD_PRIVATE_NONLINEAR_M,
        },
        "candidate_a_projected_private_cost": {
            "credential_key_binding_nonlinear_constraints": nonlinear_constraints,
            "age_predicate_private_nonlinear_constraints": AGE_PRIVATE_NONLINEAR,
            "m_candidate_a": m_candidate_a,
            "m_candidate_a_over_4987": m_candidate_a_ratio,
            "holder_authorization_constraint_reduction": holder_auth_constraint_reduction,
            "private_cost_reduction_from_m_old": private_cost_reduction_from_old_m,
            "status": "projected_estimate",
            "notes": [
                "Issuer-authenticated enrollment and unlinkability are not implemented.",
                "This projection uses the existing online presentation total N = 4987 for ratio comparison.",
            ],
        },
        "circuit_tests": {
            "valid": {
                "status": "ok",
                "expected_success": True,
            },
            "invalid_key": parse_rejection("invalid_key", notes),
            "invalid_record": parse_rejection("invalid_record", notes),
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
        print(f"collect_credential_key_binding_metrics.py: {exc}", file=sys.stderr)
        sys.exit(1)
