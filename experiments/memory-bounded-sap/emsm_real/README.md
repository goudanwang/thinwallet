# Phase 2A Streaming EMSM Prototype

This directory implements a Phase 2A EMSM path for the memory-bounded SAP experiment.

Status:

- protocol mapping: `EMSM_PROTOCOL_MAPPING_COMPLETE`
- parameter classification: `EMSM_PARAMETER_CLASSIFICATION_COMPLETE`
- RAA reference encoder: `RAA_REFERENCE_ENCODER_PASS`
- streaming RAA encoder: `STREAMING_RAA_ENCODER_PASS`
- EMSM correctness: `PAPER_FAITHFUL_STREAMING_EMSM_CORRECTNESS_PASS`
- native proof compatibility: `NATIVE_SUMCHECK_PROOF_WITH_STREAMING_EMSM_PASS`
- primary classification: `STREAMING_EMSM_BLOCKED_BY_REMOTE_H_PRIVACY`

The implementation follows the EMSM algebra:

```text
r = G e
v = z + r
em = <v, g>
dm = em - <e, h>
h = G^T g
```

and uses the RAA generator structure:

```text
G = F_r * M_sigma1 * A * M_sigma2 * A
```

Important limits:

- this is a semi-honest Phase 2A prototype;
- accumulation is tested in the BN254 scalar-field additive model, not a production curve-group prover backend;
- parameter values are `TEST_ONLY` or `PRODUCTION_UNVALIDATED`, not security-validated production tables;
- direct sparse h retrieval leaks `support(e)` to the h server in model H1;
- full EMSM privacy is not claimed.

