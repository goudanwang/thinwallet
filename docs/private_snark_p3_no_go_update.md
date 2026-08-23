# P3 No-Go Update

The P3 experiment is correct but does not improve online phone cost over the
existing P2 baseline.

## Case A: Phone Online Low but Offline O(m)

Not achieved in the tested toy model. P3-A moves triple generation to offline
phone preprocessing, but online phone work is still linear in `m`.

At `m = 16384`, P3-A measured:

- 13.644 ms phone online;
- 43.305 ms phone offline preprocessing;
- 1,572,864 bytes of phone triple storage.

If a future variant reduces online cost only by moving work offline, it may be
acceptable only if preprocessing can run during charging or idle time.

## Case B: Phone Storage O(m)

P3-A and P3-B require full triple shares on the phone. P3-C reduces pre-expansion
storage to a 32-byte simulated seed, but after expansion the toy implementation
still materializes `O(m)` triple shares.

Compressed correlations or streaming preprocessing remain required.

## Case C: Dealer Required

P3-B requires trusted preprocessing and is therefore no longer a pure phone plus
single-server setup model. It remains single-server online, but the setup model
changes.

## Case D: Simulated PCG Only

P3-C is marked:

```text
SIMULATED_PCG_NOT_SECURE
```

The compressed-correlation result is not cryptographic evidence until a real
PCG/VOLE construction is integrated and analyzed.

## Current Classification

```text
P3_NO_IMPROVEMENT_OVER_P2
```

The next step should not be MSM-specific outsourcing unless the work is narrowed
to linear/MSM subroutines. The mainline should either integrate a real PCG/VOLE
with explicit setup/storage accounting or move toward proof-system redesign.
