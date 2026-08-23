# Paper Evaluation Tables

All latency rows use five measured malicious FS6 repetitions, one worker, one
warm-up, local in-process transport, and no transcript tracing.

## Profile S Workloads

| Workload | Raw R1CS | Padded | Witness | Proof B | Token B | Wall mean ms | Prove mean ms | RSS mean KiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| S-W1 | 5,543 | 8,192 | 5,515 | 58,256 | 2,425 | 3,291.91 | 2,077.14 | 12,792.0 |
| S-W2 | 5,843 | 8,192 | 5,806 | 58,256 | 2,425 | 3,335.79 | 2,106.19 | 13,080.8 |
| S-W3 | 11,751 | 16,384 | 11,694 | 73,168 | 4,473 | 5,657.43 | 3,245.16 | 23,652.0 |
| S-W4 | 16,135 | 16,384 | 16,082 | 73,168 | 4,473 | 5,640.60 | 3,255.88 | 24,109.6 |

## Profile M Versus Profile S

| Pair | Profile M wall ms | Profile S wall ms | Profile M RSS KiB | Profile S RSS KiB |
| --- | ---: | ---: | ---: | ---: |
| W1 | 3,540.56 | 3,291.91 | 17,784.0 | 12,792.0 |
| W2 | 3,560.58 | 3,335.79 | 17,929.6 | 13,080.8 |
| W3 | 5,643.04 | 5,657.43 | 23,818.4 | 23,652.0 |
| W4 | 5,671.94 | 5,640.60 | 24,885.6 | 24,109.6 |

These intervals contain substantial run-order variance; they do not establish
that either authentication profile dominates performance.

## Cross-Padding Scaling

| WK(k,d) | Raw | Padded | q x m | Proof B | Token B | Upload B | E4 RSS KiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| (1,8) | 11,751 | 16,384 | 128 x 128 | 73,168 | 4,477 | 537,600 | 23,564 |
| (4,12) | 27,823 | 32,768 | 128 x 256 | 78,176 | 4,478 | 1,075,200 | 42,828 |
| (10,16) | 57,047 | 65,536 | 256 x 256 | 103,744 | 8,575 | 2,150,400 | 82,144 |
| (25,24) | 128,647 | 131,072 | 256 x 512 | 109,168 | 8,575 | 4,300,800 | 173,540 |
| (52,32) | 252,855 | 262,144 | 512 x 512 | 155,632 | 16,767 | 8,601,600 | 337,416 |

## Cap Matrix

| Profile W4 | 128 MiB | 192 MiB | 224 MiB | 256 MiB |
| --- | --- | --- | --- | --- |
| M | controlled reject | controlled reject | pass, 25,004 KiB RSS | pass, 25,076 KiB RSS |
| S | controlled reject | controlled reject | pass, 24,108 KiB RSS | pass, 24,160 KiB RSS |

External Ed25519 steady-state means are 0.010514 ms signing and 0.027547 ms
strict verification. Standalone verifier CLI latency, full raw samples, SD,
min/max, and 95% confidence intervals are in
`experiments/credential_workloads/results/v4c/phase_v4c_results.json`.

## Phase V4D FS7 Memory Reduction

The five-run headline gate used a 248 MiB cgroup limit, giving an 8 MiB
configured margin from 256 MiB. These runs are not included in the frozen V4C
tables above.

| Workload | Runs | Process RSS mean KiB | Process RSS max KiB | Cgroup cap MiB | Prove mean ms | Wall mean ms | Proof B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| WK(52,32) FS7 malicious | 5 | 222,008.8 | 222,308 | 248 | 84,049.64 | 113,667.92 | 155,632 |

All five resource-gate runs completed with zero OOM and zero swap and were
accepted by the unchanged verifier. The official V4D gate remains FAIL because
the measured fixture contains only one revocation path rather than one path per
credential. A single exploratory 240 MiB run also completed; it is not a
five-run stable boundary. The final seven-point planner has a maximum memory
prediction error of 4.92%.

FS7 reduces the trusted FS6 peak from 337,416 KiB to a five-run maximum of
222,308 KiB. Its mean wall latency is 1.74x the selected FS6 reference and its
mean proving latency is 2.53x, so the 1.5x latency target is not met.

The primary classification remains `PHASE_V4D_MEMORY_REDUCTION_ONLY` because
authenticated compact witness replay, full credential-by-credential relation
streaming, and multi-credential revocation streaming are not implemented.
