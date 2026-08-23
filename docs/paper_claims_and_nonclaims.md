# Paper Claims And Non-Claims

V4F status: `PHASE_V4F_PLANNER_VALIDATION_FAILED`. The workload, cap,
identity, table, and security results below are measured desktop results, but
the desktop release-candidate gate is not satisfied because the independent
seven-point planner validation has 14.85% maximum process-memory error against
the 5% target.

## Permitted Experimental Claims

- ThinWallet supports an optimized symmetric credential-authentication profile
  (Profile M) based on a native-field MiMC7 PRF-MAC and externally authenticated
  issuer-key commitment.
- ThinWallet supports a public-key issuer-authenticated signed-commitment
  profile (Profile S) using RFC 8032 Ed25519 outside the SNARK.
- Profile S authenticates the issuer without in-circuit non-native signature
  verification. The R1CS instead proves a hiding commitment opening and the
  credential predicates over the same hidden values.
- Registry-signed revocation statements authenticate the sparse-Merkle root,
  credential type, epoch, and validity interval; the R1CS binds root, epoch, and
  revocation identifier.
- One proof jointly presents multiple issuer-authenticated credentials in the
  measured project-specific Profile M and Profile S relations.
- Credential composition and revocation-policy scaling are independently
  parameterized by `WK(k,r,d,RevBackend)` and were measured through padded
  relation size `2^18`.
- Preprocessed PBMO supports the measured fragmented shared-basis commitment
  outputs. M1 remains a privacy-insecure diagnostic baseline and supports no
  privacy claim.
- H0, H1, and H2 produce byte-identical native Spartan proofs and transcript
  event streams in M0, M2, M3, and M4. The unchanged upstream libspartan 0.9.0
  verifier accepts every valid identity fixture.
- The measured M3/M4 minimum stable desktop caps are 64 MiB for H0, 256 MiB for
  H1, and 224 MiB for H2. These are controlled WSL desktop measurements, not a
  mobile-device claim.

## Required Qualification

The Profile S issuer signature is standard Ed25519, but the credential package
and native-field MiMC7 commitment are project-specific. The commitment has not
received an independent cryptographic audit. External signature verification,
issuer registry policy, nonce replay storage, revocation freshness, and clock
policy remain application responsibilities. Preprocessed PBMO changes where
private commitment MSM work is performed; it does not claim lower total proving
work.

Planner calibration and validation are separate. The final validation model
misses three validation points by more than 5% and reaches 14.85% maximum
process-memory error. Consequently no validated general planner-accuracy claim
or desktop release-candidate claim is permitted.

The network values 78.55, 205.41, 707.50, and 4,737.45 ms are PBMO
transport-only replay latency, not full proving or end-to-end presentation
latency.

## Explicit Non-Claims

- No native compatibility with every verifiable-credential standard is claimed.
- No W3C VC interoperability is claimed; no W3C package was implemented.
- No accumulator revocation support is claimed; the measured backend is the
  transparent native-field SparseMerkle construction.
- Public-key signature verification is not performed inside the SNARK.
- No independent security audit of the native-field commitment hash is claimed.
- No Android feasibility claim is made without an authorized physical ARM64
  device result.
- No production-wallet readiness or deployment claim is made.
- Complete software-state snapshot rollback is not prevented.
- Profile M is not a standard digital-signature credential.
- The prototype is not claimed to reduce total cryptographic proving work.
- No desktop release candidate is claimed while planner validation fails.

Output: `FINAL_DESKTOP_CLAIM_AUDIT_PASS`.

## V5A Physical Android Evidence

One authorized physical Samsung SM-S9110 (Galaxy S23), ARM64-v8a, Android 16
device executed the frozen ThinWallet semantics. S-W1, S-W4, H0, H1 and H2 A3
each completed five measured runs without process swap. Deterministic S-W1,
H0 and H2 proof and transcript bytes match the desktop fixtures exactly. The
unchanged verifier accepted representative proofs on Android and desktop and
rejected the measured negative fixtures.

These are single-device, headless-shell results. They do not establish
production-wallet readiness, all-device Android behavior, background-service
viability, W3C VC interoperability, accumulator revocation, independent MiMC7
audit, or complete snapshot-rollback protection. No joule claim is made.
In-process PBMO provider byte counters are not real-phone network evidence.
The frozen runner lacks a real network transport and controlled process-kill /
network failpoint interface, so real-phone network, crash-injection, and the
complete Android security gate remain incomplete. The honest primary status is
`PHASE_V5A_EVALUATION_INCOMPLETE`.

Output: `ANDROID_CLAIM_AUDIT_PASS`.

## V5B First-Device Network And Crash Evidence

The same physical Samsung SM-S9110 completed one warm-up and five measured A3
runs for each of S-W1, S-W4, H0, H1 and H2 over a real controlled Wi-Fi LAN.
The HMAC-SHA256-authenticated framed TCP path preserved deterministic native
proof bytes. Mean PBMO transport latency was 89.155, 198.705, 590.543,
2,095.375 and 2,151.607 ms respectively; mean full proving latency was
4,512.077, 7,198.310, 12,835.547, 94,088.750 and 95,237.667 ms. These data do
not support a claim that networking dominates complete presentation latency.

Real Android `kill -9` tests covered all ten lifecycle positions plus an H0
case. Real Wi-Fi interruption covered seven required S-W4 positions plus an H1
long upload. Uncertain reserved sessions recovered as `BURNED`; a completed
session remained `SPENT`; incomplete uploads emitted no proof; and the server
did not start MSM for the 15 malformed or incomplete request probes. Replay of
both a burned and a spent token was rejected.

The transport is authenticated plaintext TCP pinned to a controlled private
LAN. It is experiment-only channel security, not TLS or production channel
security. The evidence applies to one Galaxy S23 headless-shell prototype, not
all Android devices or a production wallet. No W3C VC interoperability,
accumulator revocation, independent MiMC7 audit, measured energy, cellular
performance, or complete software snapshot-rollback protection is claimed.

Output: `V5B_MOBILE_CLAIM_AUDIT_PASS`.
