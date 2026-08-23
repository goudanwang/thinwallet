# Updated Mainline Decision

Final classification:

```text
REDESIGN_CONTINUE_WITH_SUMCHECK_IOP
```

| Candidate | Phone online | Server work | Setup assumption | Standard SNARK compatible | Main blocker | Verdict |
| --------- | -----------: | ----------: | ---------------- | ------------------------- | ------------ | ------- |
| R0 standard Groth16 offload | private nonlinear core remains | FFT/MSM/linear work | none | yes | private nonlinear witness generation | ONLY_AS_BASELINE |
| R1 low-private-nonlinearity restriction | small only if circuit fits | large linear/public work | none | no by default | real credential fit unknown | CONTINUE |
| R2 offline/online preprocessed circuits | small if request-independent work is preprocessed | large online proof work | offline phone/storage | no by default | freshness, rollback, request dependence | PROMISING_BUT_NEEDS_NEW_PROOF_SYSTEM |
| R3 Sumcheck/IOP linear-message redesign | residual nonlinear checks | large linear-message/prover work | none initially | no by default | identify linear messages and sound binding | CONTINUE |
| R4 split core/extension proof | small core proof | extension proof | none initially | no by default | composition soundness | CONTINUE |
| R5 real VOLE/PCG | potentially reduced | large prover plus correlations | real cryptographic preprocessing | no by default | malicious security and setup/storage | PROMISING_BUT_NEEDS_NEW_PROOF_SYSTEM |
| R6 custom delegated proof bundle | design-dependent | design-dependent | design-dependent | no | changes verifier/proof target | PROMISING_BUT_NEEDS_NEW_PROOF_SYSTEM |

## Decision

Stop treating standard SNARK offload as the mainline. Continue with R3 as the
primary redesign target, with R1 restricted circuit prototypes and R4 split
proofs as fallback directions.

R5 should not continue as toy triples. It only becomes meaningful if a real
VOLE/PCG construction is integrated with explicit setup, storage, and malicious
security assumptions.
