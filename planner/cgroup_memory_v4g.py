#!/usr/bin/env python3
"""Conservative V4G cgroup admission; this is not a 5% prediction model."""

from planner.process_memory_v4g import MIB


def budget(process_prediction, point):
    # Service/accounting headroom plus a bounded resident spill-cache allowance.
    page_cache_allowance = 4 * MIB + 48 * point["padded_constraints"]
    expected = process_prediction["expected_process_vm_hwm_bytes"] + 4 * MIB
    conservative = process_prediction["safe_upper_bound_process_vm_hwm_bytes"] + page_cache_allowance
    return {
        "expected_cgroup_working_set_bytes": expected,
        "expected_page_cache_allowance_bytes": page_cache_allowance,
        "conservative_cgroup_upper_bound_bytes": conservative,
        "memory_high_bytes": None,
        "accuracy_claim_percent": None,
    }
