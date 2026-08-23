# Same-Commitment Bridge

The goal is to bind the phone-side small core to the same commitments used by
the R3 server-side linear path.

The implemented opening PoK proves knowledge of `x_i,rho_i` such that:

```text
A_i = x_i G + rho_i H
```

The proof uses Fiat-Shamir after fixing the full `stmt_core`, selected
commitments, and first prover messages. It does not reveal `x_i,rho_i`.

The random-linear batched opening PoK also verifies:

```text
O2_BATCHED_OPENING_POK_CORRECT
```

But it is not treated as a complete selected-opening proof:

```text
O2_INDIVIDUAL_EXTRACTION_ARGUMENT_OPEN
```

The remaining bridge problem is membership:

```text
SELECTED_COMMITMENT_MEMBERSHIP_OPEN
```

The compact R3 anchor `T` binds the full vector `A`, but the current prototype
does not provide a succinct proof that each selected `A_i` belongs to the vector
committed by `T`.
