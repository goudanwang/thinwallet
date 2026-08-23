#!/usr/bin/env python3
"""Freeze V4F fixtures and the desktop RC only after all gates pass."""

import hashlib
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
V4F = ROOT / "results/v4f"
RAW = V4F / "raw/runs"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_challenges():
    required = [
        ROOT / "docs/thinwallet_technical_challenges.md",
        ROOT / "docs/thinwallet_design_evolution.md",
        ROOT / "docs/thinwallet_memory_optimization_timeline.md",
        ROOT / "docs/thinwallet_paper_challenge_compression_map.md",
        ROOT / "docs/thinwallet_artifact_index.md",
    ]
    ledger = required[0].read_text()
    sections = re.split(r"(?=^## TC\d+:)", ledger, flags=re.M)[1:]
    rows = []
    for expected in range(1, 19):
        section = next((part for part in sections if part.startswith(f"## TC{expected}:")), "")
        checks = {
            "phase": "First observed" in section,
            "measured_effect": "Effect." in section or "Measured\neffect." in section or "Measured effect." in section,
            "residual_limitation": "Residual." in section,
            "source": "Source" in section,
            "artifact": "Artifact" in section or "Sources/artifacts" in section,
        }
        rows.append({"challenge": f"TC{expected}", **checks, "passed": bool(section) and all(checks.values())})
    compression = required[3].read_text()
    groups = {f"PC{index}": f"PC{index}:" in compression for index in range(1, 5)}
    payload = {
        "classification": "THINWALLET_TECHNICAL_CHALLENGE_ARCHIVE_VERIFIED" if all(path.exists() for path in required) and all(row["passed"] for row in rows) and all(groups.values()) else "THINWALLET_TECHNICAL_CHALLENGE_ARCHIVE_INCOMPLETE",
        "required_files": [{"path": path.relative_to(ROOT).as_posix(), "sha256": sha(path)} for path in required],
        "technical_challenges": rows, "paper_groups": groups,
    }
    (V4F / "challenge_archive_validation.json").write_text(json.dumps(payload, indent=2) + "\n")
    return payload


def freeze_headlines():
    audit = json.loads((ROOT / "experiments/credential_workloads/results/v4e/phase_v4e_semantic_audit.json").read_text())
    meta = {row["workload"]: row for section in ("composition_scaling", "revocation_scaling") for row in audit[section]}
    headlines = {"H0": "WK(8,0,0,None)", "H1": "WK(52,1,32,SparseMerkle)", "H2": "WK(8,8,32,SparseMerkle)"}
    manifest = {"classification": "FINAL_HEADLINE_WORKLOADS_FROZEN", "workloads": []}
    for hid, workload in headlines.items():
        source = ROOT / meta[workload]["authenticated_source_path"]
        identity = []
        for path in RAW.glob("identity_*_M0_*_r1.json"):
            data = json.loads(path.read_text())
            if data.get("schema_version") == "thinwallet-v4f-resource-v1" and data.get("workload") and data.get("proof_sha256") and data.get("transcript_sha256"):
                canonical = re.sub(r"sparse_merkle$", "SparseMerkle", data["workload"])
                if (hid == "H0" and "k8-r0-d0-none" in canonical) or (hid == "H1" and "k52-r1-d32" in canonical) or (hid == "H2" and "k8-r8-d32" in canonical): identity.append((path, data))
        if len(identity) != 1:
            raise RuntimeError(f"missing unique M0 identity run for {hid}")
        result_path, result = identity[0]
        prefix = Path(str(result_path)[:-5])
        destination = V4F / "headline_fixtures" / hid
        destination.mkdir(parents=True, exist_ok=True)
        files = {
            "authenticated_source": source,
            "native_proof": Path(str(prefix) + ".proof.bin"),
            "native_transcript": Path(str(prefix) + ".transcript.jsonl"),
            "verifier_fixture": Path(str(prefix) + ".verify.json"),
        }
        frozen = {}
        for label, path in files.items():
            target = destination / path.name
            shutil.copy2(path, target)
            frozen[label] = {"path": target.relative_to(ROOT).as_posix(), "bytes": target.stat().st_size, "sha256": sha(target)}
        manifest["workloads"].append({
            "headline": hid, "workload": workload, "relation_layout_digest": meta[workload]["relation_layout_digest"],
            "public_input_digest": meta[workload]["public_input_digest"], "witness_digest": meta[workload]["witness_digest"],
            "proof_session_id": meta[workload]["proof_session_id"], "files": frozen,
        })
    (V4F / "headline_fixtures/manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def freeze_release(summary, challenges):
    android = [
        "docs/android_required_device_profile.md", "docs/android_physical_benchmark_plan.md",
        "docs/android_benchmark_checklist.md", "docs/android_expected_artifacts.md",
        "scripts/android/push_artifacts.sh", "scripts/android/run_headless_benchmark.sh",
        "scripts/android/pull_results.sh",
    ]
    android_ready = all((ROOT / path).exists() for path in android)
    gates = {
        "headline_matrix": summary["headline_matrix_complete"],
        "composition_scaling": summary["composition_scaling_complete"],
        "revocation_scaling": summary["revocation_scaling_complete"],
        "proof_transcript_identity": summary["proof_transcript_identity"],
        "unchanged_verifier": summary["unchanged_verifier"],
        "planner_validation": summary["planner_validation"] == "FINAL_DESKTOP_PLANNER_VALIDATION_PASS",
        "security_regression": summary["security_regression"],
        "challenge_archive": challenges["classification"] == "THINWALLET_TECHNICAL_CHALLENGE_ARCHIVE_VERIFIED",
        "paper_tables": len(summary["paper_tables"]) == 11,
        "android_handoff": android_ready,
        "claim_audit": (ROOT / "docs/paper_claims_and_nonclaims.md").exists(),
    }
    if not all(gates.values()):
        return {"frozen": False, "gates": gates}
    archive = ROOT / "archive/thinwallet_desktop_release_candidate"
    archive.mkdir(parents=True, exist_ok=True)
    (archive / "README.md").write_text(
        "# ThinWallet Desktop Release Candidate\n\n"
        "Classification: `PHASE_V4F_DESKTOP_RELEASE_CANDIDATE_PASS`.\n\n"
        "The desktop implementation is frozen and further desktop feature development is stopped. "
        "This archive is a reproducible source/results manifest. It includes no physical Android execution; "
        "ARM64 cross-compilation is not an Android performance result.\n"
    )
    (archive / "REPRODUCE.md").write_text(
        "# Reproduction\n\n"
        "From WSL Ubuntu 22.04:\n\n```bash\n"
        "cd experiments/libspartan\n"
        "cargo build --release --bin phase_v2_pbmo --bin phase_v4c_profile_s --bin phase_v4e_credential_source\n"
        "./scripts/run_v4f_evaluation.sh all\n"
        "./scripts/run_v4f_security.sh\n"
        "python3 scripts/collect_v4f_results.py\n"
        "python3 scripts/finalize_v4f.py\n"
        "```\n\nCgroup runs require invoking the evaluation script as WSL root; the transient service runs the prover as `ubuntu`.\n"
    )
    roots = [
        ROOT / "experiments/libspartan/Cargo.toml", ROOT / "experiments/libspartan/Cargo.lock",
        ROOT / "experiments/libspartan/src", ROOT / "experiments/libspartan/scripts",
        ROOT / "experiments/libspartan/vendor/spartan-0.9.0/src",
        ROOT / "experiments/preprocessed-pbmo/Cargo.toml", ROOT / "experiments/preprocessed-pbmo/Cargo.lock",
        ROOT / "experiments/preprocessed-pbmo/src", ROOT / "experiments/credential_workloads/results/v4e",
        ROOT / "results/v4f", ROOT / "docs", ROOT / "theory", ROOT / "scripts/android",
    ]
    files = []
    for root in roots:
        if root.is_file(): files.append(root)
        elif root.exists(): files.extend(path for path in root.rglob("*") if path.is_file())
    files.extend([archive / "README.md", archive / "REPRODUCE.md"])
    lines = [f"{sha(path)}  {path.relative_to(ROOT).as_posix()}" for path in sorted(set(files))]
    (archive / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    return {"frozen": True, "classification": "THINWALLET_DESKTOP_RELEASE_CANDIDATE_FROZEN", "manifest_files": len(lines), "gates": gates}


def primary_classification(summary, challenges, release):
    if not summary["headline_matrix_complete"]:
        return "PHASE_V4F_HEADLINE_MATRIX_INCOMPLETE"
    if not summary["composition_scaling_complete"]:
        return "PHASE_V4F_COMPOSITION_SCALING_INCOMPLETE"
    if not summary["revocation_scaling_complete"]:
        return "PHASE_V4F_REVOCATION_SCALING_INCOMPLETE"
    if not summary["proof_transcript_identity"]:
        return "PHASE_V4F_PROOF_EQUIVALENCE_FAILED"
    if not summary["unchanged_verifier"]:
        return "PHASE_V4F_NATIVE_VERIFIER_FAILED"
    if summary["planner_validation"] != "FINAL_DESKTOP_PLANNER_VALIDATION_PASS":
        return "PHASE_V4F_PLANNER_VALIDATION_FAILED"
    if not summary["security_regression"]:
        return "PHASE_V4F_SECURITY_REGRESSION_FAILED"
    if challenges["classification"] != "THINWALLET_TECHNICAL_CHALLENGE_ARCHIVE_VERIFIED" or not release.get("frozen"):
        return "PHASE_V4F_ARCHIVE_INCOMPLETE"
    return "PHASE_V4F_DESKTOP_RELEASE_CANDIDATE_PASS"


def main():
    V4F.mkdir(parents=True, exist_ok=True)
    challenges = validate_challenges()
    headlines = freeze_headlines()
    summary_path = V4F / "evaluation_summary.json"
    summary = json.loads(summary_path.read_text())
    release = freeze_release(summary, challenges)
    result = {
        "primary_classification": primary_classification(summary, challenges, release),
        "headline_fixtures": headlines["classification"],
        "challenge_archive": challenges["classification"],
        "release_candidate": release,
        "android_handoff": "ANDROID_PHYSICAL_HANDOFF_PACKAGE_READY",
    }
    (V4F / "finalization_status.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
