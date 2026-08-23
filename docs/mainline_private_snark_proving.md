# Mainline: Single-Server Assisted Private SNARK Proving

Current mainline:

```text
Single-server assisted private SNARK proving.
```

The problem is to let a resource-constrained phone generate a SNARK proof with
help from one semi-honest cloud server while preserving witness privacy.

Requirements:

1. server does not learn the private witness;
2. phone online work is significantly smaller than local proving;
3. verifier does not trust the server;
4. server contribution is publicly or cryptographically checkable;
5. final proof remains compatible with a standard or clearly specified SNARK
   verifier when possible.

Current blocker:

```text
NONLINEAR_WITNESS_COMPUTATION_BLOCKER_OPEN
```
