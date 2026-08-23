# EMSM integration API design

This file defines interfaces only. It is not an EMSM implementation.

```rust
pub trait PrivateMsmOutsourcing {
    type Scalar;
    type Point;
    type PublicSetup;
    type PrivateState;
    type Request;
    type Response;
    type Error;

    fn setup(
        basis: &[Self::Point],
        parameters: &AuditedEmsmParameters,
    ) -> Result<Self::PublicSetup, Self::Error>;

    fn prepare_request(
        setup: &Self::PublicSetup,
        private_scalars: &[Self::Scalar],
        rng: &mut dyn CryptoRngCore,
    ) -> Result<(Self::Request, Self::PrivateState), Self::Error>;

    fn server_evaluate(
        setup: &Self::PublicSetup,
        request: &Self::Request,
    ) -> Result<Self::Response, Self::Error>;

    fn recover(
        setup: &Self::PublicSetup,
        state: Self::PrivateState,
        response: &Self::Response,
    ) -> Result<Self::Point, Self::Error>;

    fn verify_if_malicious(
        setup: &Self::PublicSetup,
        state: &Self::PrivateState,
        response: &Self::Response,
        recovered: &Self::Point,
    ) -> Result<(), Self::Error>;
}
```

An audited parameter object must contain the exact source identifier,
`security_bits`, field/group identity, `n`, `N`, `t`, code descriptor digest,
sampler definition, and malicious-check definition. It must reject unsupported
`m` rather than silently derive parameters.

## ThinWallet provider

```rust
pub trait IndependentEmsmCommitmentProvider {
    type Scalar;
    type Point;
    type Error;

    fn commit_ordered_rows(
        &mut self,
        rows: &[&[Self::Scalar]], // q distinct rows, each length m
        basis: &[Self::Point],    // one fixed ordered public basis
    ) -> Result<Vec<Self::Point>, Self::Error>;
}
```

Required invariants:

- output length equals `q`;
- output `i` is exactly the native commitment to row `i`;
- every row uses independent fresh EMSM randomness;
- the basis digest and order are checked;
- malformed, replayed, reordered, or duplicate requests are rejected;
- malicious verification completes before a point is released;
- native commitment blinding is applied locally after recovery;
- returned points use canonical Ristretto encoding;
- native proof encoding, transcript, and verifier are unchanged;
- reusable setup and one-time private state have explicit lifecycle accounting.

## Proposed module boundary

If and only if the parameter gap is resolved, the minimal new code surface is:

```text
experiments/emsm-rs/
  src/parameters.rs
  src/raa.rs
  src/sampler.rs
  src/protocol.rs
  src/ristretto_backend.rs
  src/wire.rs
  src/independent_provider.rs
```

The provider would be connected only at libspartan's existing prover MSM
adapter. No libspartan verifier or proof-group conversion is permitted.

