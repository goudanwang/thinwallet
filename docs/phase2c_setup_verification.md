# Phase 2C Setup Verification

Phase 2C verifies the local EMSM correction vector:

```text
h = G^T g
```

Current output:

```text
EMSM_SETUP_RELATION_DEFINED
V0_SIGNED_PREVERIFIED_BASELINE_PASS
V1_FULL_STREAMING_REDERIVATION_PASS
V2_RANDOM_LINEAR_SETUP_CHECK_PASS
PHASE2C_PASS_WITH_SIGNED_PLUS_RANDOM_CHECK
```

V0 retains the signed/preverified manifest baseline. V1 deterministically
rederives h for feasible install-time checks. V2 performs a transparent
randomized linear consistency check after `root_g` and `root_h` are fixed.

Recommended practical policy:

```text
POLICY_SIGNED_PLUS_RANDOM_CHECK
```

This removes the previous setup-correctness-only assumption for the measured
path, but it does not prove malicious-server EMSM security or Android
production security.

