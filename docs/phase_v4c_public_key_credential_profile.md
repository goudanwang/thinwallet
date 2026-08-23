# Phase V4C Public-Key Credential Profile

## Result

Primary classification: `PHASE_V4C_PUBLIC_KEY_CREDENTIAL_PROFILE_PASS`.

Profile S uses Ed25519 (`ed25519-dalek 2.2.0`) outside the SNARK and proves a
native-field MiMC7 credential-commitment opening inside the unchanged Spartan
relation. Issuer and registry signatures are application artifacts, not Spartan
proof fields.

## Named Workloads

| Workload | Raw constraints | Padded | Public inputs | Witness elements | q x m | Proof bytes | Token bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| S-W1 | 5,543 | 8,192 | 10 | 5,515 | 64 x 128 | 58,256 | 2,425 |
| S-W2 | 5,843 | 8,192 | 13 | 5,806 | 64 x 128 | 58,256 | 2,425 |
| S-W3 | 11,751 | 16,384 | 17 | 11,694 | 128 x 128 | 73,168 | 4,473 |
| S-W4 | 16,135 | 16,384 | 22 | 16,082 | 128 x 128 | 73,168 | 4,473 |

One commitment opening costs 4,381 constraints: 365 for hidden holder binding,
4,015 for the 11-block commitment, and one equality constraint. A separate
linear public-input identity row binds the issuer key digest.

## Five-Run Malicious FS6 Means

| Workload | Wall ms | SNARK prove ms | Peak RSS KiB | Mask ms | Server MSM ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| S-W1 | 3,291.91 | 2,077.14 | 12,792.0 | 7.89 | 36.28 |
| S-W2 | 3,335.79 | 2,106.19 | 13,080.8 | 8.05 | 36.31 |
| S-W3 | 5,657.43 | 3,245.16 | 23,652.0 | 15.78 | 73.44 |
| S-W4 | 5,640.60 | 3,255.88 | 24,109.6 | 15.88 | 72.45 |

Steady-state external Ed25519 signing averaged 0.010514 ms and strict
verification averaged 0.027547 ms after 20 warm-ups. The runner's separate cold
process/application-audit latency is retained separately and is not part of
`SNARK prove ms`. Upload latency is null because local in-process transport was
not separately timed; bytes are reported instead.

## Useful Cross-Padding Workloads

| WK(k,d) | Raw | Padded | q x m | Proof | Token | Upload | E4 RSS KiB | E4 wall ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| (1,8) | 11,751 | 16,384 | 128 x 128 | 73,168 | 4,477 | 537,600 | 23,564 | 5,935.90 |
| (4,12) | 27,823 | 32,768 | 128 x 256 | 78,176 | 4,478 | 1,075,200 | 42,828 | 10,418.56 |
| (10,16) | 57,047 | 65,536 | 256 x 256 | 103,744 | 8,575 | 2,150,400 | 82,144 | 18,909.23 |
| (25,24) | 128,647 | 131,072 | 256 x 512 | 109,168 | 8,575 | 4,300,800 | 173,540 | 35,080.60 |
| (52,32) | 252,855 | 262,144 | 512 x 512 | 155,632 | 16,767 | 8,601,600 | 337,416 | 65,423.99 |

Every row consists only of credential commitments, holder/equality/predicate
constraints, and the requested revocation path. No dummy constraints were
added. E0/E3/E4 serialized proofs are identical for all five rows, and the
unchanged upstream verifier accepts them. Full transcript-event byte equality
was additionally recorded for S-W1 through S-W4.

## Caps And Variance

Both W4 and S-W4 receive controlled planner rejection at 128 and 192 MiB, and
complete at 224 and 256 MiB. The five-run W4 semi-honest and malicious 95%
intervals overlap widely. Each mode has one similarly low outlier, so the prior
malicious-lower-than-semi result is classified as measurement variance; cache
versus scheduling contribution remains unresolved.

The 2^18 S-WK workload used about 329.5 MiB FS6 RSS. The prior 2^18-under-256-MiB
claim applies to its frozen synthetic relation, not every credential relation.

The old 78.55, 205.41, 707.50, and 4,737.45 ms network values are PBMO
transport-only replay latencies. They are neither full proof latency nor
end-to-end presentation latency.
