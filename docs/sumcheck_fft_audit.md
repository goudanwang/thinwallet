# FFT Audit

Client prover audit result: `CLIENT_PROVER_FFT_FREE_PASS`.

Audited paths:

- `experiments/memory-bounded-sap/local_baseline`
- `experiments/memory-bounded-sap/streaming_sumcheck`
- `experiments/memory-bounded-sap/witness_stream`
- `experiments/memory-bounded-sap/remote_msm`
- `experiments/memory-bounded-sap/remote_parameters`

The audit checks for hidden FFT/NTT/LDE/FRI path tokens and records runtime transform calls as zero. The benign status name `INTERNAL_FFT_FREE_MULTILINEAR_SUMCHECK_PHASE1_BACKEND` is ignored to avoid a false positive.

This audit only covers the selected Phase 1 client path. It does not certify
separate Circom/Groth16 experiments.
