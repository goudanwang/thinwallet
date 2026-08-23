# Phase V4E Desktop Semantic Status

Primary classification: `PHASE_V4E_EVALUATION_INCOMPLETE`.

## Completed

* `WK(k,r,d,RevBackend)` and `WK_52_32_LEGACY` migration are implemented.
* XChaCha20-Poly1305 compact source, session/relation/RevSet/registry/public-input
  binding, bounded record replay, canonical scalar/index checks and journal
  rollback detection are implemented.
* In-memory and authenticated replay A/B/C entries, witness, public inputs,
  transcript and serialized proof are byte-identical for the deterministic
  `WK(8,2,32,SparseMerkle)` identity fixture. Both the patched and unchanged
  upstream verifier accept both proofs.
* All V4E source/path negative tests pass. Existing Profile S strict Ed25519 and
  PBMO token/malicious/crash tests were rerun and pass.
* `WC(k)` and `WR(r)` relation shapes were measured in
  `experiments/credential_workloads/results/v4e/phase_v4e_semantic_audit.json`.

## Measured Relation Scaling

| Workload | Raw constraints | Padded | Public inputs | Witness elements | Sparse entries | Source bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `WK(1,1,32,SparseMerkle)` | 29,271 | 32,768 | 17 | 29,262 | 110,151 | 1,939 |
| `WK(4,1,32,SparseMerkle)` | 42,423 | 65,536 | 32 | 42,426 | 159,543 | 3,316 |
| `WK(10,1,32,SparseMerkle)` | 68,727 | 131,072 | 62 | 68,754 | 258,327 | 6,070 |
| `WK(25,1,32,SparseMerkle)` | 134,487 | 262,144 | 137 | 134,574 | 505,287 | 12,955 |
| `WK(52,1,32,SparseMerkle)` | 252,855 | 262,144 | 272 | 253,050 | 949,815 | 25,348 |

| Workload | Raw constraints | Delta from `WK(8,0,0,None)` | Path siblings | Source bytes |
| --- | ---: | ---: | ---: | ---: |
| `WK(8,0,0,None)` | 36,531 | 0 | 0 | 4,076 |
| `WK(8,1,32,SparseMerkle)` | 59,959 | 23,428 | 32 | 5,152 |
| `WK(8,2,32,SparseMerkle)` | 83,387 | 46,856 | 64 | 6,220 |
| `WK(8,4,32,SparseMerkle)` | 130,243 | 93,712 | 128 | 8,356 |
| `WK(8,8,32,SparseMerkle)` | 223,955 | 187,424 | 256 | 12,628 |

## Not Yet Measured

For the corrected headline suites, PBMO token/proof/upload/download size, process and
cgroup memory, temporary storage, proof latency, transport-only latency, server
MSM latency and end-to-end latency remain `null`. The full 64/96/128/192/224/256
MiB native/PBMO/FS6/FS7 matrix and five-repetition boundary runs were not
executed. These headline fields remain `null`, not inferred.

The separate native identity run produced byte-identical 106,544-byte proofs
(`96eb4a77837b8b1bc638a7339a251b0b07881df879df4767a28df3b82ab63be2`) and
21,951-event, 3,109,214-byte transcripts
(`1cb710e14f9e30bb39352deec814cd204de66097323cb40790b0a93618716d04`).
In-memory/authenticated-replay proving times were 32,863.229/32,640.364 ms and
peaks were 466.035/466.129 MiB. This is an uncapped native identity test, not a
headline FS7 measurement.

The retained V4D historical fixture is now correctly named
`WK(52,1,32,SparseMerkle)`: five 248 MiB-cgroup runs had process peaks
`[222308,221732,221916,221852,222236] KiB`, proving times
`[84276.541571,83386.932153,84290.955048,84170.948437,84122.805136] ms`,
wall times `[113602.224991,113103.515815,114199.760707,113608.614148,113825.478721] ms`,
and 155,632-byte proofs. These are cold/local full-run historical measurements;
they are not substituted for the missing corrected V4E mode/cap matrix.

The network values 78.55, 205.41, 707.50 and 4737.45 ms remain transport/server
components from prior experiments and are not labeled full proving latency.

Because evaluation and full prover-path identity are incomplete, no ThinWallet
desktop release-candidate archive has been frozen.
