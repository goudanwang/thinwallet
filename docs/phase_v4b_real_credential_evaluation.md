# Phase V4B Real Credential Evaluation

Classification: `PHASE_V4B_REAL_CREDENTIAL_EVALUATION_PASS`

Phase V3E is frozen at `archive/phase_v3e_256m_fs6/`. The current primary
unresolved project blocker is `NO_AUTHORIZED_PHYSICAL_ARM64_ANDROID_DEVICE`.
`DENSE_MATRIX_VALUE_BACKEND_BLOCKED` applies only to further large synthetic
memory reduction, not to these credential workloads.

## Credential Relations

| Workload | Raw constraints | Variables | Public inputs | Spartan padded | q/m | Padding |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| W1 | 5,178 | 5,149 | 7 | 16,384 | 128/128 | 11,206 |
| W2 | 5,478 | 5,440 | 10 | 16,384 | 128/128 | 10,906 |
| W3 | 11,385 | 11,328 | 13 | 16,384 | 128/128 | 4,999 |
| W4 | 15,404 | 15,350 | 15 | 16,384 | 128/128 | 980 |

The backend's square fragmented layout requires an even logarithm, so W1/W2
are padded to `2^14` although their raw relations fit below that size. Every
workload uses 128 ordered commitment outputs, a 4,471-byte encoded PBMO token,
537,600 upload bytes, and 4,096 download bytes. FS6 temporary storage is
25,689,088 bytes for W1/W2 and 42,990,592 bytes for W3/W4. Proofs are 62,664
bytes for W1/W2 and 73,168 bytes for W3/W4.

Issuer authentication is a 91-round MiMC7 native-field PRF-MAC with an
externally authenticated issuer-key commitment. It costs 3,652 constraints per
credential. It is a non-standard symmetric construction, not a credential
signature, and depends on the registry/issuer authenticating the key
commitment.

## Online Results

Operational runs disable transcript JSON tracing. Trace-enabled fixtures are
retained separately for equivalence checks.

| Workload | Semi wall ms | Semi prove ms | Semi RSS KiB | Malicious wall ms | Malicious prove ms | Malicious RSS KiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| W1 | 3,760.077 | 2,149.846 | 17,796 | 3,832.529 | 2,204.756 | 17,604 |
| W2 | 3,401.162 | 2,205.408 | 17,960 | 3,818.776 | 2,213.216 | 17,884 |
| W3 | 5,909.349 | 3,309.299 | 23,820 | 6,085.123 | 3,293.790 | 23,692 |
| W4 | 6,009.773 | 3,185.490 | 24,948 | 5,200.691 | 3,242.670 | 24,820 |

The W4 malicious run measured 67.840 ms server MSM, 13.602 ms masking,
0.015 ms recovery, and 5.552 ms malicious batch checking. These are desktop
WSL measurements and do not establish Android feasibility.

## Equivalence

For each workload, E0 native provider, E1 plaintext remote, E2 in-memory PBMO,
E3 FS6 semi-honest, and E4 FS6 malicious produced byte-identical proofs and
transcripts. Event counts were 10,460, 10,466, 12,232, and 12,236 for W1-W4.
Every serialized proof was accepted by the unchanged upstream libspartan 0.9.0
verifier. The per-workload proof hashes are retained in
`results/phase_v4b_summary.json`.

## Memory Caps

W4 E4 was run under both `ulimit -v` and the FS6 budget planner. At 192 MiB the
planner rejected the run before proving. At 224 MiB and above it succeeded.
The 256 MiB headline repetitions were `5/5`, with RSS
`[24952, 24760, 24948, 24820, 24632]` KiB (mean 24,822.4 KiB) and wall times
`[5787.614, 5751.087, 5743.102, 5722.618, 5787.670]` ms. All proofs verified.

## Revocation

W3/W4 use depth-8 sparse-Merkle non-membership with a zero leaf, authenticated
private revocation index, enforced path directions, public root, and root epoch
equal to request epoch. Revocation adds 5,907 constraints: 5,840 hashes, 57
index/range constraints, eight path selections, one root equality, and one
freshness equality. Valid and boundary fixtures pass; revoked leaf, stale root,
and malformed path fixtures fail. External root authenticity and the verifier's
accepted freshness window remain assumptions.

## Token Preprocessing

Each encoded token is 4,471 bytes with 128 correction points. Idle generation
was 103.8-104.7 ms at 3,584 KiB peak RSS. While a foreground proof ran it was
91.8-100.1 ms at 3,188-3,316 KiB; one-worker runs were 101.7-106.1 ms at
3,584 KiB. Storage for 1/8/32/128 tokens is 4,471/35,768/143,072/572,288 bytes.
This is offline preprocessing and does not reduce total computation.

## Network Replay

The desktop userspace replay used the measured 537,600-byte upload, 4,096-byte
download, and 71.700 ms reference server duration. End-to-end times were
78.55 ms (LAN), 205.41 ms (stable Wi-Fi-like), 707.50 ms (moderate cellular-like),
and 4,737.44 ms (high-latency cellular-like). The high-latency interrupted-upload
case applied the durable policy `BURNED`, never returning a reserved token to
`AVAILABLE`. This is not a kernel `tc` or Android result.

## Second PBMO Application

The independent application is 32 batched Pedersen-style private vectors over
one shared 128-point Ristretto basis. Its token is 1,414 bytes. Semi-honest and
malicious outputs exactly match the 32 local ordered commitments; measured
online times were 23.212 ms and 24.708 ms, and an injected output corruption was
rejected. Integration is in `phase_v4b_second_pbmo.rs`, outside the libspartan
prover call site.

## Baselines

| Baseline | Wall ms | Prove ms | Peak RSS KiB | Status |
| --- | ---: | ---: | ---: | --- |
| B0 native local proof | 1,896.301 | 1,055.781 | 110,052 | measured |
| B1 local fragmented MSM | 4,339.537 | 1,736.094 | 108,460 | measured |
| B2 plaintext remote MSM | 4,287.178 | 1,738.426 | 108,456 | measured |
| B3 independent EMSM | null | null | null | projected 128 correction points / 4,096 bytes only |
| B4 in-memory PBMO | 4,444.772 | 1,781.608 | 108,588 | measured |
| B5 FS6 semi-honest | 6,009.773 | 3,185.490 | 24,948 | measured |
| B6 FS6 malicious | 5,200.691 | 3,242.670 | 24,820 | measured |

B3 is not a completed secure libspartan implementation.

## Ablation

The frozen `2^18` synthetic scaling fixture attributes RSS from A0 through A6
as 998,503; 998,936; 867,816.9; 514,154.4; 375,133.6; 262,456; and 245,401.6
KiB. Corresponding wall means are 11,667.6; 37,828.4; 46,486.5; 62,107.9;
73,635.9; 37,862.1; and 39,478.5 ms. A3-A6 temporary storage was
503,315,456; 411,040,768; 578,949,319; and 411,040,768 bytes. Earlier A0-A2
temporary-storage and read/write subdivisions were not directly instrumented
and remain `null`. A7 separates ephemeral spill durability from the durable
token journal: spill fsync is zero, while token terminal state remains `SPENT`.
All measured stages preserve the expected proof hash.

## Security And Accounting

Credential negatives reject forged MAC, modified attributes/issuer/holder,
wrong nonce, expiry, revocation, stale root, malformed path, and cross-credential
mismatch. PBMO tests are 9/9, patched libspartan tests 54/54 plus doc tests 3/3,
streaming tests 4/4, and crash semantics 1/1. Token reuse, replay/corruption,
state corruption, and post-reservation failure remain covered. Complete local
snapshot rollback remains `SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED`.

The W4 E4 latency ledger accounts for 99.999998% of the Rust monotonic wall.
Nested Sumcheck, product, recomputation, spill, PBMO, journal, and cleanup
timers are retained without double-counting. WSL's Rust monotonic clock and
`/usr/bin/time` differed by 531.291 ms, so both raw clocks are reported.
