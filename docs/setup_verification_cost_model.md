# Setup Verification Cost Model

V1:

- deterministic;
- approximately O(N) structured group/field work;
- uses external files and bounded working memory;
- best for high-assurance install-time verification.

V2:

- randomized;
- computes one MSM over h and one MSM over g per check round;
- computes dense beta = G alpha through streaming RAA;
- bounded-memory and suitable as a practical install-time check.

Phase 2C records:

- peak RSS;
- allocator live bytes;
- temporary disk;
- bytes downloaded;
- group-operation model;
- field-operation model;
- install-time latency.

Large n remains behind `MEMORY_BOUNDED_SAP_LARGE_BENCH=1`.

