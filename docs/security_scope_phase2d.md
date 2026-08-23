# Security Scope Phase 2D

Phase 2D hardens the EMSM group layer:

- prototype additive-field group operations are removed from the production
  Phase 2D execution path;
- h generation uses real BN254 G1 points;
- V1 and V2 setup checks use real group MSMs;
- semi-honest and malicious EMSM correctness checks pass over real group
  operations;
- native proof regression remains accepted with unchanged internal verifier.

Primary classification:

```text
PHASE2D_PASS_PRODUCTION_GROUP_MALICIOUS
```

Still not claimed:

- production Sumcheck SNARK backend migration;
- 128-bit curve security;
- empirical proof of RAM bounded-by-chunk at large enough sizes;
- side-channel resistance;
- Android deployment;
- NDSS readiness.

Memory classification:

```text
PRODUCTION_RAM_RESULT_INCONCLUSIVE
```

