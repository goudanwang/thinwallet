# Sumcheck Backend Selection

Selected backend: `INTERNAL_FFT_FREE_MULTILINEAR_SUMCHECK_PHASE1_BACKEND`.

Backend audit result: `SUMCHECK_BACKEND_SELECTED`.

Candidates checked:

- B0 Spartan-style Sumcheck backend: not selected because no production dependency/API was found in this repository.
- B1 HyperPlonk-style multilinear PIOP: not selected because no production dependency/API was found.
- B2 Nova/HyperNova-related backend: not selected because no usable native backend was present.
- B3 internal FFT-free multilinear Sumcheck backend: selected only for Phase 1 architecture validation.

This is not a production SNARK backend. It is a local native Sumcheck wrapper with JSON proof serialization and a native verifier used as the correctness source of truth for Phase 1.

