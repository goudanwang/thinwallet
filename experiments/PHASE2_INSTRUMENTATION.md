# Phase 2 Instrumentation

Instrumentation is compile-time available but runtime opt-in through
`THINWALLET_INSTRUMENTATION=1`. Its observers do not append to the protocol
transcript and do not change proof serialization, verifier code, PBMO framing,
or token state transitions.

The transcript sidecar is an ordered event observer. It stores operation type,
hashed domain label, input length, input hash, and a rolling event-stream
digest. Merlin does not expose its internal sponge digest, so the recorded
digest is explicitly not claimed to be Merlin state. Raw transcript inputs,
Fiat-Shamir challenges, witness values, masks, seeds, tokens, and PSKs are not
written.

Commitment observations store only point length and SHA-256. The aggregate
digest covers ordered unblinded and blinded encodings, while the JSONL sidecar
does not expose those encodings.

`memory.csv` and `io.csv` sample Linux `/proc/self/status`,
`/proc/self/smaps_rollup`, and `/proc/self/io` at the configured interval
(50 ms for Phase 2). Unavailable kernel fields are `null`. Phase events use
monotonic time and RAII begin/end guards. Temporary-storage accounting scans a
unique per-run root and separates Sumcheck, opening, PBMO spool, and
miscellaneous files. The root is created on WSL's native temporary filesystem;
placing file-backed prover state on `/mnt/*` DrvFS is excluded because the
store relies on Linux `sync_data` and `posix_fadvise(DONTNEED)` semantics.

Network byte counts come from bytes actually encoded and read by the PBMO TCP
framing layer, including metadata and authentication tags. Native and
memory-only modes assert zero connections and zero network bytes.
