# Streaming Witness Design

Phase 1 defines two witness sources:

- synthetic witness stream;
- credential-like witness stream.

The synthetic stream emits deterministic field chunks without retaining the full trace. The credential-like stream is marked `CREDENTIAL_WITNESS_STREAM_PARTIAL` because it only models ordered field emissions and does not integrate a real credential circuit backend.

Measured WSL witness-generation peak Python allocation:

| n | status | peak Python alloc MB |
| -: | --- | -: |
| 4096 | `SYNTHETIC_WITNESS_STREAM_PASS` | 0.2668 |
| 16384 | `SYNTHETIC_WITNESS_STREAM_PASS` | 0.5328 |
| 65536 | `SYNTHETIC_WITNESS_STREAM_PASS` | 0.5328 |

Excluded from Phase 1:

- issuer-signature verification;
- credential schema enforcement;
- revocation;
- Android wallet integration;
- final private credential presentation.

