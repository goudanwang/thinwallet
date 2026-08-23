# Phase 1 Open Problems

First remaining blocker: implement or import a real streaming EMSM/PCS backend that preserves witness privacy while keeping the client memory-bounded.

Other open problems:

- replace the internal Phase 1 backend with a production Sumcheck SNARK backend;
- prove native verifier compatibility for the production backend;
- avoid witness materialization in the transcript-comparison harness;
- implement credential-like witness generation against the actual credential relation;
- prove remote parameter correctness beyond Merkle integrity;
- define malicious-server security for aborts, replay, malformed group elements, and cross-proof state reuse.

Until these are solved, Phase 1 must not be described as full private outsourcing.

