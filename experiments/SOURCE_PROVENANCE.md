# Source Provenance

Phase 2 uses `source-tree-hash` provenance because this workspace is not
necessarily a Git checkout. Every raw run manifest records:

- SHA-256 of the release executable actually invoked;
- SHA-256 of `experiments/libspartan/Cargo.lock`;
- a deterministic SHA-256 over sorted relative path, length, and contents for
  the runner plus the Rust source trees used by libspartan, the baseline
  verifier, PBMO, and instrumentation;
- the exact inclusion manifest and file count.

Generated results, target directories, temporary state, logs, and credentials
are excluded. A source edit changes the source-tree hash even if the executable
has not yet been rebuilt; the independent binary hash makes that mismatch
visible. Git commit and dirty state remain `null` when no `.git` metadata is
available.
