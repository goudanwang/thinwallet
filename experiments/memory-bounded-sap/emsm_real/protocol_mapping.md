# Protocol Mapping

Output: `EMSM_PROTOCOL_MAPPING_COMPLETE`.

| Paper step | Code path |
| --- | --- |
| Setup | `raa_parameters.make_parameters`, `server_streaming_msm.make_basis`, `remote_h.compute_h_vector`, `remote_h.MerkleHStore` |
| Encrypt | `sparse_noise.sample_sparse_noise`, `raa_encoder_streaming.StreamingRaaEncoder`, `streaming_encrypt.streaming_encrypt` |
| Evaluate | `server_streaming_msm.ServerStreamingMsm.evaluate` |
| Decrypt | `remote_h.sparse_h_inner_product`, then `dm = em - <e,h>` |

The implementation enforces request/session binding, vector-length binding, chunk offsets, duplicate chunk rejection, and finalization checks.

Limits:

- the native backend is still `INTERNAL_FFT_FREE_MULTILINEAR_SUMCHECK_PHASE1_BACKEND`;
- group operations are modeled over the BN254 scalar-field additive group for Phase 2A correctness tests;
- setup correctness of `h = G^T g` is preverified by the local setup routine, not proved to the verifier.

