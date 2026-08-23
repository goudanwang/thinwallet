# Profile S Security Argument

This is a reduction-style security argument for the implemented composition,
not a universally composable proof and not an independent audit.

## Assumptions

1. RFC 8032 Ed25519 as implemented by `ed25519-dalek 2.2.0` is EUF-CMA secure,
   and `verify_strict` enforces the selected canonical/weak-key policy.
2. The authenticated issuer registry maps each issuer identity and public-key
   ID to the intended Ed25519 verification key.
3. The native-field MiMC7 commitment is binding and hiding for independently
   sampled high-entropy salts.
4. The Spartan proof has knowledge soundness and zero knowledge for the encoded
   R1CS under its existing Fiat-Shamir/random-oracle assumptions.
5. The application compares the typed verified signature statement with the
   exact proof public inputs before calling the prover and verifier.
6. The registry revocation signing key, identity, freshness policy, and clock
   are authenticated application inputs.

## Acceptance Argument

For an accepted Profile S presentation, the application first establishes a
valid issuer signature for the exact `(protocol_version, credential_type,
cred_com, issuance_epoch)` tuple under the registry-selected key. The proof
public inputs bind that tuple and issuer identity. Knowledge soundness then
implies an opening known to the prover; commitment binding prevents a different
credential from opening the same signed commitment, and the R1CS evaluates the
predicates, holder/nonce binding, disclosure, and revocation path over those
same opening wires. The presentation nonce and request digest prevent accepting
the same proof under a different verifier session, subject to verifier nonce
freshness enforcement.

## Attack Analysis

- Commitment substitution: changing `cred_com` invalidates either the issuer
  signature or the R1CS opening equality.
- Issuer-key substitution: the public-key ID is checked against the issuer
  registry and the exact R1CS input; a server-selected key is not accepted.
- Signature replay: replay for a different type, commitment, epoch, or protocol
  domain fails. Replay of the identical signed credential is intentional; the
  presentation nonce must still be fresh.
- Cross-credential signature reuse: each signed commitment has a separate typed
  verified statement; S-W4 binds both openings and cross-credential predicates.
- Salt reuse: it does not directly permit forgery, but can weaken hiding and
  linkability. Issuers must sample a fresh salt; deterministic fixture salts are
  test-only.
- Nonce replay: the SNARK binds holder state to the public nonce/request digest;
  the verifier must reject reused nonces at the application layer.
- Credential-type confusion: the type is present in the commitment, signature,
  public input, registry lookup, and revocation statement.
- Encoding ambiguity: fixed widths, explicit domains, big-endian integers,
  canonical scalar decoding, exact package length, and no trailing bytes remove
  multiple-encoding acceptance in the implemented package.
- Revocation substitution/freshness: the registry signature covers root, type,
  epoch, and validity window; the R1CS binds root, epoch, and revocation ID.

Remaining limitations include the unaudited project-specific commitment hash,
application-layer clock/nonce storage, and complete software snapshot rollback.

Output: `PROFILE_S_SECURITY_ARGUMENT_COMPLETE`.
