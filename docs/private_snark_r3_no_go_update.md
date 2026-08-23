# R3 No-Go Update

R3 improves the design space but does not close the full private SNARK problem.

## Masked Mode

R3-M is correct, but it is blocked for descriptors whose correction requires the
phone to evaluate a large transform over the mask.

Marker:

```text
R3_MASKED_MODE_BLOCKED_BY_CORRECTION
```

Structured sparse descriptors remain interesting, but FFT-like or prefix-heavy
descriptors repeat the P1-style phone correction problem.

## Committed Mode

R3-C avoids phone linear correction in the toy model and gives the best phone
online profile.

Marker:

```text
R3_COMMITTED_MODE_REQUIRES_CUSTOM_PROOF_BUNDLE
```

This is promising only if the committed-linear proof and private-core proof can
be made sound under a public verifier.

## Open Gaps

```text
PRIVATE_CORE_SOUNDNESS_OPEN
R3_STANDARD_SNARK_COMPATIBILITY_OPEN
```

The next step should be an R3 committed-mode security proof and concrete
committed-linear verification design. If that fails, move to R4 split proof or
R1 restricted credential circuits.
