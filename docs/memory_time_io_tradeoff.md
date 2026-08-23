# Memory, Time, and IO Tradeoff

WSL Phase 1 local baseline:

| n | local prover ms | peak RSS MB | peak Python alloc MB |
| -: | -: | -: | -: |
| 4096 | 42.694 | 19.5000 | 0.477 |
| 16384 | 167.359 | 22.9766 | 1.862 |
| 65536 | 738.198 | 37.1055 | 7.521 |

Streaming Sumcheck performs two full reads per round plus one folded-table write per round. The measured IO amplification is approximately 6.0x for the tested powers of two.

The local baseline is faster and simpler but materializes the witness/table. Streaming mode preserves transcript equality and shifts fold tables to disk, but the Phase 1 harness still materializes witness values for comparison, so RAM scaling remains inconclusive.
