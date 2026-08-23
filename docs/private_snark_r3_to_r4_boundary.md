# R3 to R4 Boundary

Once the phone generates a separate ZK proof for the nonlinear core, and the
server generates a separate proof for the linear extension, the construction is
structurally a split proof system.

Therefore successful R3 small-core ZK naturally becomes an R3/R4 hybrid.

The current prototype confirms:

```text
R3_SELECTED_OPENING_POK_PASS
R3_LINEAR_CORE_ZK_BINDING_PASS
R3_MULTIPLICATION_CORE_ZK_OPEN
SELECTED_COMMITMENT_MEMBERSHIP_OPEN
```

The next boundary decision is:

- continue R3/R4 hybrid only if selected membership under `T` can be solved with
  `O(s)` or `O(s log N)` phone work;
- formally switch to R4 split proof if the core proof is naturally separate from
  the R3 committed-linear proof;
- stop claiming R3 progress if multiplication/private range core remains open.

If core proof cannot naturally embed into R3, classify as:

```text
SWITCH_TO_R4_SPLIT_PROOF
```
