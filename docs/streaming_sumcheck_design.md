# Streaming Sumcheck Design

The Phase 1 relation is a multilinear table sum over a vector of BN254 scalar-field values. The in-memory prover and the streaming prover generate the same Fiat-Shamir Sumcheck transcript.

Streaming mode uses an external fold store:

- pass 1 of each round reads the current table to compute the round message;
- Fiat-Shamir derives the challenge from the transcript prefix and message;
- pass 2 reads the same table again and writes the folded table.

Measured result: `STREAMING_SUMCHECK_TRANSCRIPT_MATCH_PASS`.

The WSL run measured:

| n | B | passes | peak RSS MB | peak Python alloc MB | IO amplification |
| -: | -: | -: | -: | -: | -: |
| 4096 | 1024 | 24 | 37.1055 | 0.734 | 5.9990 |
| 4096 | 4096 | 24 | 37.1055 | 0.777 | 5.9990 |
| 16384 | 1024 | 28 | 37.1055 | 2.897 | 5.9998 |
| 16384 | 4096 | 28 | 37.1055 | 2.897 | 5.9998 |
| 16384 | 16384 | 28 | 37.1055 | 3.102 | 5.9998 |
| 65536 | 1024 | 32 | 45.2031 | 11.600 | 5.9999 |
| 65536 | 4096 | 32 | 45.2031 | 11.600 | 5.9999 |
| 65536 | 16384 | 32 | 45.2031 | 11.600 | 5.9999 |

Classification: `STREAMING_RAM_RESULT_INCONCLUSIVE`. The current comparison harness still materializes the witness to compare against the in-memory transcript, so Phase 1 does not yet prove full O(B) client memory for end-to-end witness production.
