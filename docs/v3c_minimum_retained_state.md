# Phase V3C Minimum Retained State

Status: `FS3_MINIMUM_RETAINED_STATE_IDENTIFIED`

| State | Classification | Reason |
| --- | --- | --- |
| Active fold tables | `STREAM_PAIRED` | Canonical low/high pairs are read in bounded chunks. |
| Inactive product layers | `SPILL_AND_RELOAD` | FS3 authenticated state-store path remains valid. |
| Active product hash layer | `FUSE_WITH_CONSUMER` | FS4 constructs one polynomial and immediately emits its product tree. |
| Dot-product inputs | `STREAM_SEQUENTIAL` | FS4 writes directly from borrowed slices without full clones. |
| Relation after last use | `RECOMPUTE_FROM_PARENT` | Deterministic relation reconstruction is unchanged. |
| Dense MLE and address tables | `RETAIN_REQUIRED` | Later hash/opening proofs need transcript-dependent evaluations. |
| Transcript messages | `RETAIN_REQUIRED` | Fiat-Shamir challenge is unavailable before the current message is absorbed. |

The estimated minimum retained logical state for the current implementation is
206,651,392 bytes: retained dense/sparse/R1CS/commitment/PBMO state plus the
measured 25,165,824-byte bounded arena peak. Adding the unchanged 111 MiB
runtime reserve gives a current-implementation lower-bound estimate of
323,043,328 bytes (308.08 MiB). This is not a cryptographic lower bound.

A Sumcheck coefficient pass and its next fold cannot be one physical pass:
the fold challenge is derived only after the round polynomial is appended to
the transcript. FS4 therefore fuses consumers where the transcript permits it
and records the unavoidable second sequential pass as a transcript barrier.
