#!/usr/bin/env python3
"""Build V4F summaries and paper tables from measured run artifacts."""

import csv
import hashlib
import json
import math
import re
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RAW = ROOT / "results/v4f/raw/runs"
OUT = ROOT / "results/v4f"
AUDIT = ROOT / "experiments/credential_workloads/results/v4e/phase_v4e_semantic_audit.json"
CAPS = [64, 96, 128, 192, 224, 256]
HEADLINES = {
    "H0": "WK(8,0,0,None)",
    "H1": "WK(52,1,32,SparseMerkle)",
    "H2": "WK(8,8,32,SparseMerkle)",
}
MODE_LABELS = {
    "M0": "native local in-memory prover",
    "M1": "plaintext remote MSM; privacy-insecure diagnostic baseline",
    "M2": "Preprocessed PBMO in-memory; malicious-server integrity",
    "M3": "FS7 semi-honest PBMO",
    "M4": "FS7 malicious PBMO",
}


def paper_name(name):
    match = re.fullmatch(r"S-WK-k(\d+)-r(\d+)-d(\d+)-(.+)", name)
    if not match:
        return name
    backend = {"none": "None", "expiry_only": "ExpiryOnly", "sparse_merkle": "SparseMerkle"}.get(match[4], match[4])
    return f"WK({match[1]},{match[2]},{match[3]},{backend})"


def stats(values):
    values = [float(value) for value in values if value is not None]
    if not values:
        return {key: None for key in ("mean", "median", "standard_deviation", "minimum", "maximum", "ci95_low", "ci95_high") } | {"raw": [], "count": 0}
    mean = statistics.fmean(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    critical = {2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776}.get(len(values), 1.96)
    half = critical * sd / math.sqrt(len(values)) if len(values) > 1 else 0.0
    return {
        "raw": values, "count": len(values), "mean": mean, "median": statistics.median(values),
        "standard_deviation": sd, "minimum": min(values), "maximum": max(values),
        "ci95_low": mean - half, "ci95_high": mean + half,
    }


def load_runs():
    runs = []
    for path in sorted(RAW.glob("*.json")):
        if path.name.endswith((".proof.json", ".plan.json", ".cgroup.json", ".verify.json")):
            continue
        try:
            item = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        if item.get("schema_version") != "thinwallet-v4f-resource-v1":
            continue
        item["artifact_path"] = path.relative_to(ROOT).as_posix()
        item.setdefault("provenance_tag", path.name.split("_S_WK_", 1)[0])
        item["paper_workload"] = paper_name(item["workload"])
        runs.append(item)
    return runs


def mean_field(group, getter):
    return stats([getter(item) for item in group])


def minimum_stable(runs, workload, mode):
    passing = sorted({item["cap_mib"] for item in runs if item["paper_workload"] == workload and item["mode"] == mode and item["provenance_tag"] == "cap" and item["result"] == "PASS" and item["cap_mib"] is not None})
    return passing[0] if passing else None


def provenance(group):
    return ";".join(item["artifact_path"] for item in group)


def write_table(name, rows):
    for directory in ["json", "csv", "markdown", "latex"]:
        (OUT / directory).mkdir(parents=True, exist_ok=True)
    (OUT / "json" / f"{name}.json").write_text(json.dumps(rows, indent=2) + "\n")
    columns = sorted({key for row in rows for key in row}) if rows else []
    with (OUT / "csv" / f"{name}.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value, separators=(",", ":")) if isinstance(value, (dict, list)) else value for key, value in row.items()})
    def cell(value):
        if value is None: return "null"
        if isinstance(value, (dict, list)): return json.dumps(value, separators=(",", ":"))
        return str(value).replace("|", "\\|")
    markdown = [f"# {name.replace('_', ' ').title()}", "", "| " + " | ".join(columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"]
    markdown += ["| " + " | ".join(cell(row.get(column)) for column in columns) + " |" for row in rows]
    (OUT / "markdown" / f"{name}.md").write_text("\n".join(markdown) + "\n")
    escaped = lambda value: cell(value).replace("_", "\\_").replace("%", "\\%")
    latex = ["\\begin{tabular}{" + "l" * len(columns) + "}", " \\toprule", " & ".join(escaped(c) for c in columns) + " \\\\", " \\midrule"]
    latex += [" & ".join(escaped(row.get(c)) for c in columns) + " \\\\" for row in rows]
    latex += [" \\bottomrule", "\\end{tabular}"]
    (OUT / "latex" / f"{name}.tex").write_text("\n".join(latex) + "\n")


def main():
    runs = load_runs()
    audit = json.loads(AUDIT.read_text())
    metadata = {}
    for section in ("composition_scaling", "revocation_scaling", "revocation_policy_profiles"):
        for row in audit[section]: metadata[row["workload"]] = row

    headline_rows = []
    mode_rows = []
    cap_rows = []
    latency_rows = []
    minimum_caps = {}
    for hid, workload in HEADLINES.items():
        meta = metadata[workload]
        minimum_caps[hid] = {mode: minimum_stable(runs, workload, mode) for mode in ("M3", "M4")}
        headline_rows.append({
            "headline": hid, "workload": workload, "raw_constraints": meta["raw_constraints"],
            "padded_constraints": meta["padded_constraints"], "q": meta["q"], "m": meta["m"],
            "public_inputs": meta["public_inputs"], "witness_elements": meta["witness_elements"],
            "source_fixture": meta["authenticated_source_path"], "relation_layout_digest": meta["relation_layout_digest"],
            "public_input_digest": meta["public_input_digest"], "witness_digest": meta["witness_digest"],
            "units": "constraints/elements/bytes", "repetition_count": None,
            "result_provenance": "experiments/credential_workloads/results/v4e/phase_v4e_semantic_audit.json",
        })
        for mode in MODE_LABELS:
            selected_cap = None if mode in ("M0", "M1", "M2") else minimum_caps[hid][mode]
            group = [r for r in runs if r["paper_workload"] == workload and r["mode"] == mode and r["provenance_tag"] == "headline" and r["cap_mib"] == selected_cap and r["result"] == "PASS"]
            prove = mean_field(group, lambda x: x["phase_latency_ms"]["total_prove"])
            verify = mean_field(group, lambda x: x["phase_latency_ms"]["upstream_verifier"])
            process = mean_field(group, lambda x: x["resources"]["process_vm_hwm_bytes"])
            cgroup = mean_field(group, lambda x: x["resources"]["cgroup_memory_peak_bytes"])
            mode_rows.append({
                "headline": hid, "workload": workload, "mode": mode, "mode_definition": MODE_LABELS[mode],
                "privacy_model": "none; diagnostic only" if mode == "M1" else ("local witness" if mode == "M0" else "masked PBMO"),
                "malicious_server_protection": mode in ("M2", "M4"), "preprocessing_required": mode in ("M2", "M3", "M4"),
                "cap_mib": selected_cap, "repetition_count": len(group), "prove_ms": prove,
                "verifier_ms": verify, "process_vm_hwm_bytes": process, "cgroup_peak_bytes": cgroup,
                "token_size_bytes": group[0].get("patched_result", {}).get("token_size_bytes") if group else None,
                "proof_size_bytes": group[0].get("proof_size_bytes") if group else None,
                "upload_bytes": ((group[0].get("patched_result") or {}).get("full_commitment_report") or {}).get("metrics", {}).get("upload_bytes") if group else None,
                "download_bytes": ((group[0].get("patched_result") or {}).get("full_commitment_report") or {}).get("metrics", {}).get("download_bytes") if group else None,
                "temporary_storage_bytes": mean_field(group, lambda x: x["resources"]["temporary_file_maximum_bytes"]),
                "proof_byte_identity": None, "unchanged_verifier_compatible": all((g.get("external_upstream_verifier") or {}).get("accepted") is True for g in group) if group else None,
                "units": "bytes/milliseconds", "result_provenance": provenance(group),
            })
            if group:
                latency_rows.append({"headline": hid, "workload": workload, "mode": mode, "cap_mib": selected_cap, "repetition_count": len(group), "phase_latency_ms": {key: stats([g["phase_latency_ms"].get(key) for g in group]) for key in group[0]["phase_latency_ms"]}, "units": "milliseconds", "result_provenance": provenance(group)})
        for mode in ("M3", "M4"):
            for cap in CAPS:
                group = [r for r in runs if r["paper_workload"] == workload and r["mode"] == mode and r["cap_mib"] == cap and r["provenance_tag"] in ("cap", "boundary")]
                first = next((g for g in group if g["repetition"] == 1), None)
                cap_rows.append({"headline": hid, "workload": workload, "mode": mode, "cap_mib": cap, "repetition_count": len(group), "result": first["result"] if first else "NOT_MEASURED", "process_vm_hwm_bytes": stats([g["resources"]["process_vm_hwm_bytes"] for g in group]), "cgroup_peak_bytes": stats([g["resources"]["cgroup_memory_peak_bytes"] for g in group]), "planner_predicted_peak_bytes": first["resources"]["planner_predicted_peak_bytes"] if first else None, "units": "MiB/bytes", "result_provenance": provenance(group)})

    composition_rows = []
    for k in [1, 4, 10, 25, 52]:
        workload = f"WK({k},1,32,SparseMerkle)"; meta = metadata[workload]
        group = [r for r in runs if r["paper_workload"] == workload and r["mode"] == "M4" and r["provenance_tag"] == "composition" and r["result"] == "PASS"]
        composition_rows.append({"workload": workload, "mode": "M4", "repetition_count": len(group), "raw_constraints": meta["raw_constraints"], "padded_constraints": meta["padded_constraints"], "padding_ratio": meta["padded_constraints"] / meta["raw_constraints"], "public_inputs": meta["public_inputs"], "witness_elements": meta["witness_elements"], "sparse_nonzero_entries": meta["sparse_nonzero_entries"], "q": meta["q"], "m": meta["m"], "proof_size_bytes": group[0].get("proof_size_bytes") if group else None, "token_size_bytes": (group[0].get("patched_result") or {}).get("token_size_bytes") if group else None, "process_vm_hwm_bytes": mean_field(group, lambda x: x["resources"]["process_vm_hwm_bytes"]), "cgroup_peak_bytes": mean_field(group, lambda x: x["resources"]["cgroup_memory_peak_bytes"]), "temporary_storage_bytes": mean_field(group, lambda x: x["resources"]["temporary_file_maximum_bytes"]), "bytes_read": mean_field(group, lambda x: x["resources"]["bytes_read"]), "bytes_written": mean_field(group, lambda x: x["resources"]["bytes_written"]), "prove_ms": mean_field(group, lambda x: x["phase_latency_ms"]["total_prove"]), "verifier_ms": mean_field(group, lambda x: x["phase_latency_ms"]["upstream_verifier"]), "units": "constraints/elements/bytes/milliseconds", "result_provenance": provenance(group)})

    revocation_rows = []
    for rcount in [0, 1, 2, 4, 8]:
        workload = "WK(8,0,0,None)" if rcount == 0 else f"WK(8,{rcount},32,SparseMerkle)"; meta = metadata[workload]
        group = [r for r in runs if r["paper_workload"] == workload and r["mode"] == "M4" and r["provenance_tag"] == "revocation" and r["result"] == "PASS"]
        revocation_rows.append({"workload": workload, "mode": "M4", "repetition_count": len(group), "raw_constraints": meta["raw_constraints"], "padded_constraints": meta["padded_constraints"], "padding_ratio": meta["padded_constraints"] / meta["raw_constraints"], "path_siblings": meta["path_sibling_count"], "source_size_bytes": meta["authenticated_source_bytes"], "marginal_raw_constraints_from_r0": meta["raw_constraint_delta_from_r0"], "expected_per_check_constraints": 23428 if rcount else None, "process_vm_hwm_bytes": mean_field(group, lambda x: x["resources"]["process_vm_hwm_bytes"]), "cgroup_peak_bytes": mean_field(group, lambda x: x["resources"]["cgroup_memory_peak_bytes"]), "temporary_storage_bytes": mean_field(group, lambda x: x["resources"]["temporary_file_maximum_bytes"]), "bytes_read": mean_field(group, lambda x: x["resources"]["bytes_read"]), "bytes_written": mean_field(group, lambda x: x["resources"]["bytes_written"]), "prove_ms": mean_field(group, lambda x: x["phase_latency_ms"]["total_prove"]), "verifier_ms": mean_field(group, lambda x: x["phase_latency_ms"]["upstream_verifier"]), "proof_size_bytes": group[0].get("proof_size_bytes") if group else None, "units": "constraints/bytes/milliseconds", "result_provenance": provenance(group)})

    identity_rows = []
    identity_pass = True
    verifier_pass = True
    for hid, workload in HEADLINES.items():
        group = [r for r in runs if r["paper_workload"] == workload and r["mode"] in ("M0", "M2", "M3", "M4") and r["provenance_tag"] == "identity" and r["result"] == "PASS"]
        proof_hashes = {g["proof_sha256"] for g in group}; transcript_hashes = {g["transcript_sha256"] for g in group}
        passed = len(group) == 4 and len(proof_hashes) == 1 and len(transcript_hashes) == 1 and None not in transcript_hashes
        accepted = len(group) == 4 and all((g.get("external_upstream_verifier") or {}).get("accepted") is True for g in group)
        identity_pass &= passed; verifier_pass &= accepted
        identity_rows.append({"headline": hid, "workload": workload, "modes": "M0,M2,M3,M4", "repetition_count": len(group), "proof_sha256": next(iter(proof_hashes)) if len(proof_hashes) == 1 else None, "transcript_sha256": next(iter(transcript_hashes)) if len(transcript_hashes) == 1 else None, "proof_byte_identical": passed, "transcript_byte_identical": passed, "unchanged_verifier_accepts": accepted, "units": "bytes/hash", "result_provenance": provenance(group)})

    validation_workloads = [HEADLINES["H0"], HEADLINES["H1"], HEADLINES["H2"], "WK(1,1,32,SparseMerkle)", "WK(4,1,32,SparseMerkle)", "WK(25,1,32,SparseMerkle)", "WK(8,2,32,SparseMerkle)"]
    planner_rows = []
    for workload in validation_workloads:
        candidates = [r for r in runs if r["paper_workload"] == workload and r["mode"] == "M4" and r["result"] == "PASS" and r["provenance_tag"] in ("headline", "composition", "revocation")]
        if not candidates: continue
        run = sorted(candidates, key=lambda x: x["repetition"])[0]
        predicted = run["resources"]["planner_predicted_peak_bytes"]; measured = run["resources"]["process_vm_hwm_bytes"]
        error = abs(predicted - measured) / measured * 100 if predicted and measured else None
        planner_rows.append({"set": "validation", "workload": workload, "mode": "M4", "repetition_count": 1, "predicted_process_peak_bytes": predicted, "measured_process_peak_bytes": measured, "predicted_cgroup_peak_bytes": None, "measured_cgroup_peak_bytes": run["resources"]["cgroup_memory_peak_bytes"], "predicted_temporary_storage_bytes": (run.get("memory_plan") or {}).get("estimated_temporary_storage_bytes"), "measured_temporary_storage_bytes": run["resources"]["temporary_file_maximum_bytes"], "prediction_error_percent": error, "units": "bytes/percent", "result_provenance": run["artifact_path"]})
    planner_max_error = max((row["prediction_error_percent"] for row in planner_rows if row["prediction_error_percent"] is not None), default=None)
    planner_pass = len(planner_rows) >= 7 and planner_max_error <= 5

    network_rows = [{"profile": name, "workload": "PBMO transport replay fixture", "mode": "transport-only", "repetition_count": None, "transport_only_replay_ms": latency, "local_prove_ms": None, "server_msm_ms": None, "complete_presentation_ms": "NOT_MEASURED", "units": "milliseconds", "result_provenance": "retained pre-V4F transport replay profiles"} for name, latency in (("LAN", 78.55), ("Wi-Fi", 205.41), ("moderate cellular", 707.50), ("high latency", 4737.45))]
    security_path = OUT / "security_regression.json"
    security = json.loads(security_path.read_text()) if security_path.exists() else {"all_passed": False, "tests": []}
    security_rows = [{"workload": "security regression", "mode": "native/PBMO", "repetition_count": 1, "test": row.get("name"), "passed": row.get("passed"), "units": "boolean", "result_provenance": security_path.relative_to(ROOT).as_posix()} for row in security.get("tests", [])]
    ablation_path = OUT / "ablation_consolidation.json"
    ablation_rows = json.loads(ablation_path.read_text()) if ablation_path.exists() else []

    tables = {
        "headline_workloads": headline_rows, "execution_mode_baseline": mode_rows,
        "cap_boundaries": cap_rows, "composition_scaling": composition_rows,
        "revocation_scaling": revocation_rows, "latency_breakdown": latency_rows,
        "network": network_rows, "security_tests": security_rows,
        "ablations": ablation_rows, "memory_planner_validation": planner_rows,
        "proof_transcript_identity": identity_rows,
    }
    for name, rows in tables.items(): write_table(name, rows)
    summary = {
        "headline_workloads": HEADLINES, "execution_modes": MODE_LABELS,
        "minimum_stable_caps": minimum_caps,
        "headline_matrix_complete": all(row["repetition_count"] == 5 for row in mode_rows),
        "composition_scaling_complete": all(row["repetition_count"] >= (5 if row["workload"] != "WK(8,2,32,SparseMerkle)" else 3) for row in composition_rows),
        "revocation_scaling_complete": all(row["repetition_count"] >= (3 if row["workload"] == "WK(8,2,32,SparseMerkle)" else 5) for row in revocation_rows),
        "proof_transcript_identity": identity_pass,
        "unchanged_verifier": verifier_pass,
        "planner_validation_points": len(planner_rows), "planner_max_error_percent": planner_max_error,
        "planner_validation": "FINAL_DESKTOP_PLANNER_VALIDATION_PASS" if planner_pass else "FINAL_DESKTOP_PLANNER_VALIDATION_FAIL",
        "security_regression": security.get("all_passed", False),
        "network_metric_consolidation": "PBMO transport-only; complete network presentation NOT_MEASURED",
        "software_only_snapshot_rollback_not_prevented": True,
        "paper_tables": sorted(tables),
    }
    (OUT / "evaluation_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, separators=(",", ":")))


if __name__ == "__main__":
    main()
