# PBMO Second-Application Requirements

The second application must expose a real logical private commitment with a
shared public basis and multiple exact ordered outputs, while differing from
libspartan's dense witness polynomial.

It must provide:

- a precise private matrix/public basis relation and native correctness oracle;
- stable basis, backend, relation, layout, and dimension identifiers;
- an unchanged native proof/verifier path for byte or semantic equivalence;
- row/chunk streaming without full private-matrix materialization;
- independent token generation and one-time lifecycle integration;
- semi-honest and post-output malicious integrity modes;
- negative tests for relation mismatch, token reuse, replay, permutation,
  corruption, crash recovery, and whole-snapshot rollback limitations;
- offline/online latency, memory, persistent storage, upload/download, and local
  group-work accounting.

Candidates that require adaptive client re-entry, upload the basis online, or
hide an `Omega(qm)` client vector do not validate the Phase V2 abstraction.
