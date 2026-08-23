# Research Mainline

Primary mainline: `MEMORY_BOUNDED_SUMCHECK_SERVER_AIDED_SNARK`.

The goal is a memory-bounded, single-server, private server-aided prover for an
FFT-free Sumcheck-based zk-SNARK. Phase 1 deliberately does not claim NDSS
readiness, complete private outsourcing, issuer-signed credential support, or
a production end-to-end delegation protocol.

The native verifier of the selected backend is the source of truth. Any remote, streaming, or external-storage variant must eventually produce a proof accepted by that unchanged verifier.
