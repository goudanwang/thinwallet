# EMSM baseline fairness policy

Any future independent-EMSM result is admissible only if all rules below are
satisfied.

1. Use the same curve and scalar field as the ThinWallet result.
2. Use the same MSM library unless an official implementation cannot be
   adapted; any difference must be reported and prevents direct backend timing
   attribution.
3. Compare at the same claimed security level with source-backed parameters.
4. Use the identical `q,m` workload and relation instance.
5. Return all `q` native points in the original order.
6. Report semi-honest and malicious modes separately.
7. Report reusable setup, one-time offline state, and online work separately.
8. Report client and server work separately.
9. Count communication from actual canonical encoded bytes.
10. Include all setup/preprocessing storage, including code descriptors,
    basis-dependent `h`, validation material, and persisted private state.
11. Never reuse `e`, `e_ck`, `c`, or other randomness where the construction
    requires freshness.
12. Do not charge reusable public setup per request, but do report its build,
    validation, storage, and amortization denominator.
13. Do not hide one-time private state generation or storage inside public
    setup.
14. Do not use PBMO's aggregate malicious check to optimize EMSM unless the
    result is separately labelled as a hybrid and backed by a new proof.
15. Do not lower `lambda`, `n`, `N`, `t`, code distance, or malicious checking
    merely to make EMSM fit the workload.
16. Preserve failed runs, rejected setup, malformed requests, and negative
    tests; do not delete unfavorable data.

Additional frozen requirements:

- the ThinWallet native verifier must accept the resulting unchanged proof;
- transcript and proof bytes must be compared where deterministic conditions
  permit;
- setup generation and verification must use the exact audited sampler;
- every result must include source, lock, binary, parameter, and setup hashes;
- paper and artifact results may be cited, but must not be merged with local
  measurements as if produced by one implementation.

