#!/usr/bin/env python3
"""Evaluation helpers for the frozen V4G phase-aware process model."""

import json
from pathlib import Path

MIB = 1024 * 1024


def linear_mib(coefficients, values):
    return sum(coefficient * value for coefficient, value in zip(coefficients, values))


def predict(model, point):
    n_unit = point["padded_constraints"] / 65536
    sparse_unit = point["sparse_nonzero_entries"] / 100000
    matrix_domain = 1 << (point["max_sparse_matrix_entries"] - 1).bit_length()
    matrix_domain_unit = matrix_domain / 100000
    malicious = 1 if point["mode"] in ("M2", "M4") else 0

    source = model["phases"]["SourcePhase"]
    source_bytes = (
        source["fixed_runtime_reserve_bytes"]
        + source["thread_stack_reserve_bytes"]
        + source["frame_buffer_bytes"]
        + source["allocator_margin_bytes"]
        + source["source_byte_multiplier"] * point["source_size_bytes"]
        + source["credential_record_bytes"] * point["k"]
    )
    relation_mib = linear_mib(
        model["phases"]["RelationBuildPhase"]["coefficients_mib"],
        [1, sparse_unit, matrix_domain_unit],
    )
    instance_mib = linear_mib(
        model["phases"]["InstanceFinalizationPhase"]["coefficients_mib"],
        [1, n_unit, sparse_unit, matrix_domain_unit],
    )
    if point["mode"] == "M2":
        proving_mib = linear_mib(
            model["phases"]["ProvingPhase"]["m2_coefficients_mib"],
            [1, n_unit, sparse_unit, matrix_domain_unit],
        )
    else:
        proving_mib = linear_mib(
            model["phases"]["ProvingPhase"]["streaming_coefficients_mib"],
            [1, n_unit, point["k"], point["r"], malicious],
        )
    pbmo = model["phases"]["PBMOPhase"]
    pbmo_bytes = (
        pbmo["fixed_bytes"]
        + pbmo["token_multiplier"] * point.get("token_bytes", 0)
        + pbmo["bounded_chunk_bytes"]
        + malicious * pbmo["malicious_check_bytes"]
    )
    opening = model["phases"]["OpeningPhase"]
    opening_bytes = (
        opening["fixed_bytes"]
        + opening["bytes_per_padded_constraint"] * point["padded_constraints"]
        + opening["bytes_per_fragmented_output"] * point["q"]
    )
    assembly = model["phases"]["ProofAssemblyPhase"]
    assembly_bytes = assembly["fixed_bytes"] + assembly["bytes_per_public_input"] * point["public_inputs"]

    phases = {
        "SourcePhase": round(source_bytes),
        "RelationBuildPhase": round(max(0, relation_mib) * MIB),
        "InstanceFinalizationPhase": round(max(0, instance_mib) * MIB),
        "ProvingPhase": round(max(0, proving_mib) * MIB),
        "PBMOPhase": round(pbmo_bytes),
        "OpeningPhase": round(opening_bytes),
        "ProofAssemblyPhase": round(assembly_bytes),
    }
    peak_phase = max(phases, key=phases.get)
    expected = phases[peak_phase]
    safe = expected + model["safety"]["calibrated_one_sided_residual_bytes"] + model["safety"]["required_execution_safety_margin_bytes"]
    return {
        "phase_predictions_bytes": phases,
        "predicted_peak_phase": peak_phase,
        "expected_process_vm_hwm_bytes": expected,
        "safe_upper_bound_process_vm_hwm_bytes": safe,
    }


def load(path=None):
    if path is None:
        path = Path(__file__).resolve().parent / "models/process_memory_v4g.json"
    return json.loads(Path(path).read_text())
