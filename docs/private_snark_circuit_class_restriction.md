# Circuit Class Restriction

The audit suggests that phone-light private proving is plausible only for
restricted circuit classes.

## Friendly Class

A circuit is more promising when:

- private-private multiplications are small;
- private hash/signature/Merkle work is avoided or compiled away;
- most work is public, linear, or committed-linear;
- request-dependent private nonlinear checks form a small core.

This corresponds to:

```text
LINEAR_OFFLOAD_FRIENDLY
LOW_PRIVATE_NONLINEARITY
```

## Unfriendly Class

A circuit is not suitable for phone-light private proving when:

- it contains many private-private multiplications;
- private hashing dominates;
- in-circuit signatures dominate;
- Merkle paths are private and repeated;
- range/bit decomposition is large and request-dependent.

The modeled profiles classify age predicates, range proofs, Poseidon preimages,
Merkle paths, EdDSA verification, and realistic credential presentations as
private-nonlinearity heavy or phone-light unlikely.

## Consequence

The mainline should not promise arbitrary R1CS private proving. It should either
restrict supported circuits or change the proof-system interface so the phone
only handles a small private nonlinear core.
