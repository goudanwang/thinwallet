# Remote Parameter Storage

Phase 1 implements a remote proving-parameter manifest and Merkle root check.

Measured marker: `REMOTE_PARAMETER_STORAGE_PASS`.

The manifest records:

- parameter version;
- curve ID;
- backend ID;
- vector length;
- Merkle root;
- chunk digest.

The experiment also emits `EMSM_SETUP_GLOBAL_CORRECTNESS_ASSUMED_OR_PREVERIFIED`. This means parameter storage integrity is represented, but EMSM setup correctness is not implemented as a full cryptographic proof in Phase 1.

