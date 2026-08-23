# Phase V4 Android ThinWallet Plan

## Entry Conditions

Begin only after Phase V3 identifies a client process whose live state is
bounded independently of the full prover witness and whose proof remains
accepted by the unchanged verifier.

## Work Items

- Implement Android Keystore-backed `TokenStoreKeyProvider` and a real
  monotonic/external rollback provider, keeping software fallback explicitly
  non-production.
- Port the bounded scalar stream, token mmap/read path, reserve-before-send
  journal, timeout burn, and recovery scanner.
- Replace in-process transport with authenticated, backpressured streaming and
  replay-safe server session state.
- Measure supported devices for memory, latency, flash write amplification,
  thermal behavior, battery energy, crash recovery, and network interruption.
- Test key loss, device migration, backup/restore, cloud-wallet synchronization,
  token depletion, and secure replenishment as separate protocol concerns.

No Android or mobile-feasibility claim follows from Phase V2.

