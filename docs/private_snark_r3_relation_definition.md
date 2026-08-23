# R3 Committed-Mode Relation Definition

The current custom relation uses the following public statement:

```text
stmt = (
    protocol_domain,
    request_digest,
    verifier_domain_digest,
    descriptor_family_id,
    N,
    q,
    private_core_type,
    private_core_indices_digest,
    committed_state_anchor T,
    linear_descriptors D_1, ..., D_q,
    committed_linear_outputs U_1, ..., U_q,
    optional batched output U_star,
    phone_activation_public_key,
    activation_digest,
    public_predicate_parameters
)
```

Server-side private state:

```text
A = (A_0, ..., A_{N-1})
A_i = Commit(x_i, rho_i)
```

R3 currently does not prove opening knowledge of all `A_i`. It only audits
linear evaluations over the committed vector anchor.

Phone-side private state:

```text
x_S
activation_secret_key
private_core_auxiliary_witness
```

The committed-mode proof bundle should prove:

1. `T` binds server committed vector `A`.
2. For every `j`, `U_j = LinearEval(A, D_j)`.
3. Sumcheck/IOP transcript is consistent with `U_j` and the public relation.
4. Phone activation authorizes this request, descriptor set, `T`, and private-core claim.
5. Private core contribution is bound to the same statement.

Open gaps:

```text
A opening semantics are not proved globally.
Private core to A consistency requires selected-opening bridge or equivalent.
Standard SNARK compatibility is open.
```
