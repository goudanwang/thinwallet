# Security Parameters

Output: `EMSM_PARAMETER_CLASSIFICATION_COMPLETE`.

The Phase 2A table uses:

```text
N = 4n
t = max(128, ceil(sqrt(N)))
```

This avoids forbidden constant choices such as `t = 1`, `t = 2`, or `t = O(1)`, but it is not a validated production parameter table.

Parameter classes:

- `TEST_ONLY`: small CI-sized rows below the validated range.
- `PAPER_MATCHING`: no Phase 2A row is claimed as paper-matching.
- `PRODUCTION_UNVALIDATED`: uses the intended RAA shape and nonconstant t, but lacks independent security validation.

Current rows are written to `experiments/memory-bounded-sap/results/emsm_mapping.json` and `phase2a_summary.json`.

