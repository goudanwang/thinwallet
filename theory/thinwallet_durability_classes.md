# ThinWallet Durability Classes

Status: `THINWALLET_DURABILITY_CLASSIFICATION_COMPLETE`

## Classes

| State | Class | Required behavior |
| --- | --- | --- |
| PBMO token reservation transition | `SECURITY_CRITICAL_DURABLE` | Authenticated journal write and durable sync complete before masked network bytes may be released. |
| PBMO terminal `SPENT`/`BURNED` transition | `SECURITY_CRITICAL_DURABLE` | Journal and token record remain crash consistent. |
| Authenticated token journal metadata | `SECURITY_CRITICAL_DURABLE` | Preserve file and required directory syncs. |
| Sumcheck fold and product-layer files | `EPHEMERAL_CORRECTNESS_ONLY` | Check writes, authenticate/checksum metadata, reject corruption, but do not fsync. |
| Dense MLE and opening spill files | `EPHEMERAL_CORRECTNESS_ONLY` | Same proof-attempt lifetime; loss aborts the proof. |
| Checkpoint metadata for the current proof | `REGENERABLE_CACHE` | Bound to source digest/session/version; safe to discard on crash. |
| Serialized proof | `FINAL_OUTPUT` | Returned only after successful proof assembly and token finalization; caller controls archival durability. |

## Crash boundary

A crash may discard the entire proof attempt and leave non-durable spill files.
The durable token reservation remains authoritative. Recovery converts an
unfinalized `RESERVED` token to `BURNED`; the same masked material cannot be
used to resume or restart the proof. Checksums, authenticated metadata,
session/challenge binding, read-after-write checks, write-error propagation,
and normal cleanup remain enabled for ephemeral objects.

The V3D instrumented run skipped 5,948 ephemeral object syncs and executed zero
ephemeral fsync calls. It retained nine security-critical token sync calls,
measured at 29.51 ms, and completed with token state `SPENT`. A combined crash
test reserved a token durably, simulated process loss during an ephemeral
spill, and observed `BURNED` after recovery.

This separation does not solve host snapshot rollback. The retained
classification is `SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED`.

Outputs: `EPHEMERAL_STATE_FSYNC_REMOVED` and
`PBMO_TOKEN_DURABILITY_PRESERVED`.
