# R3 Small-Core Relation

The small-core statement is:

```text
stmt_core = (
    protocol_domain,
    request_digest,
    committed_state_anchor T,
    selected_commitments A_S,
    selected_indices_digest S_digest,
    private_core_type,
    private_core_public_parameters,
    private_core_output_commitment C_z,
    R3_linear_transcript_digest,
    activation_digest
)
```

The phone witness is:

```text
wit_core = (
    x_i for i in S,
    rho_i for i in S,
    z,
    rho_z,
    private_core_auxiliary_witness
)
```

The implemented same-group toy relation proves:

```text
A_i = x_i G + rho_i H, for i in S
C_z = z G + rho_z H
z = sum_i alpha_i x_i + beta
```

The phone does not prove openings for all `N` commitments. It proves only
selected entries indexed by `S`.

Implemented markers:

```text
R3_SELECTED_OPENING_POK_PASS
R3_LINEAR_CORE_ZK_BINDING_PASS
R3_LINEAR_PATH_FROZEN
```

This is still a custom proof bundle, not a Groth16 or Plonk proof.
