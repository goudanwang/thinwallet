# ThinWallet Security Model

## Parties And Trust

- The holder controls private credential fields, commitment salt, and holder
  secret. The holder application verifies issuer and registry signatures before
  proving.
- The issuer is trusted only through its authenticated public-key registry
  entry for Profile S, or through the external symmetric key-commitment
  authority for Profile M.
- The revocation registry signs typed, epoch-bound root statements. The
  verifier supplies the expected registry identity and freshness policy.
- The server may be malicious. PBMO tokens are one-time, authenticated, bound to
  relation/session/basis metadata, and checked against corrupted/reordered/
  replayed outputs.
- The verifier uses unchanged upstream libspartan verification and independently
  checks the application-layer issuer/registry transcript.

## Protected Properties

Under the documented signature, commitment, SNARK, Fiat-Shamir, registry, and
PBMO assumptions, the measured Profile S rejects issuer/key/type/commitment/
epoch substitution, opening mismatches, wrong holder/nonce, expired or revoked
credentials, malformed paths, cross-credential mismatches, PBMO token reuse,
server-output replay, and malicious output corruption.

Private fields and salt are not public inputs. The externally visible
credential commitment and issuer public-key ID can be stable and therefore may
be linkable. This phase does not implement unlinkable credentials.

## Availability And State Limits

Controlled budget rejection is safe failure, not proof completion. Crash-safe
token reservation burns a token after any possible release. However,
`SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED` remains in force: an attacker
able to restore the complete software and persistent-state snapshot can bypass
purely software monotonicity assumptions.

No Android, W3C interoperability, production-wallet, hardware-keystore, or
independent-audit claim follows from this desktop model.
