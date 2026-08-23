# Phase V3 OOM Boundary Plan

## Objective

Measure the complete memory boundary for native libspartan, plaintext cloud
proving, non-streaming assisted proving, preprocessed PBMO, and the full
ThinWallet streaming path without treating the Phase V2 smoke test as a mobile
result.

## Controlled Variables

- Pin backend revision, Rust toolchain, curve, relation generator, witness,
  prover randomness, CPU affinity, and transcript label.
- Run each mode in a fresh process under 64, 96, 128, 192, 256, 384, 512, 768,
  and 1,024 MiB caps where supported.
- Separate setup, token generation, witness preparation, commitment, remaining
  prover, verification, network simulation, and persistent I/O.
- Repeat successful points at least five times and retain all exit statuses,
  `time -v` output, cgroup events, HWM, proof hashes, and verifier results.
- Sweep relation sizes around each first failure rather than only powers of two.

## Required Outcomes

Determine the largest completed relation, first allocation failure, memory
composition, latency distribution, token mmap/storage behavior, upload/download,
and whether PBMO materially lowers client memory after the rest of the prover is
separated from the client process.

