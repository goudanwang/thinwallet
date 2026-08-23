# WK(52,32) Peak Attribution

The low-overhead FS7 run reached a maximum process `VmHWM` of 222,308 KiB.
This document does not claim `WK52_2P18_PEAK_EXACTLY_ATTRIBUTED`: allocator
capacity and lifetime records for every category were unavailable without an
instrumented allocator that substantially perturbs RSS.

## Phase Cut

One uncapped final run recorded:

| Boundary | Current RSS MiB | VmHWM MiB |
| --- | ---: | ---: |
| Before relation entries | 2.25 | 2.38 |
| After relation entries | 116.08 | 138.00 |
| After `Instance` | 171.59 | 203.33 |
| After encoding | 163.89 | 203.33 |
| After relation release | 88.39 | 203.33 |
| After proof | 59.59 | 217.02 |

The final peak occurs inside proving, after the relation builder has been
released.

## Directly Accounted Objects

| Object | Logical bytes | Peak-resident interpretation |
| --- | ---: | --- |
| Expanded witness assignment | 8,388,608 | Retained prover input |
| Sparse relation entries | 45,591,120 | Released before prover peak |
| External matrix-value tables | 50,331,648 | File-backed, not wholly resident |
| Address/read/audit tables | 29,360,128 | Retained compact `u32` tables |
| FS6 dereference equality sources | 16,777,216 | Retained prover source |
| Active fold buffer budget | 8,388,608 | Bounded external fold buffers |
| PBMO upload spool | 8,388,608 | File-backed |

The former `usize` address/read/audit representation required 58,720,256
logical bytes. Compact `u32` storage removes 29,360,128 bytes while preserving
the exact field values and proof bytes.

## Unavailable Split

Independent live/capacity values remain `null` for MiMC rounds, holder and
range predicates, revocation hash intermediates, dense MLEs, Sumcheck state,
product layers, openings, commitment layouts, transcript buffers, allocator
residual, and unknown allocations. These values are not inferred by subtracting
known objects from RSS because their lifetimes differ.

The current WK fixture also emits only one depth-32 revocation path for
credential 0. It must not be described as storing or streaming 52 paths.

The complete nullable allocation schema is in
`experiments/v4d/wk52_peak_live_cut.json`.
