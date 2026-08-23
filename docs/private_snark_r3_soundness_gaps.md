# R3 Soundness Gaps

## Bridge Gap

The audit constructs:

```text
x_good satisfies the private core.
A_bad commits to a different x_bad.
server linear outputs are computed from A_bad.
phone core value is computed from x_good.
```

Current reveal-only R3 accepts this mixed state:

```text
R3_PRIVATE_CORE_COMMITMENT_BRIDGE_GAP_DETECTED
```

B2 public selected openings reject the attack:

```text
R3_SELECTED_OPENING_PUBLIC_TOY_BLOCKS_BRIDGE_GAP
```

## Placeholder Gap

The ZK selected-opening path is only a placeholder:

```text
R3_SELECTED_OPENING_ZK_PLACEHOLDER
SELECTED_OPENING_ZK_NOT_IMPLEMENTED
```

It must not be treated as a privacy-preserving proof.

## Compatibility Gap

R3 remains a custom composed proof bundle:

```text
R3_REMAINS_CUSTOM_PROOF_BUNDLE
```

It is not a Groth16 or Plonk proof.
