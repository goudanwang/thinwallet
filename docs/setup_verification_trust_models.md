# Setup Verification Trust Models

V0 signed preverified manifest:

- trusts a setup signer/auditor;
- efficient and bounded-memory;
- useful baseline and fallback.

V1 full streaming rederivation:

- transparent deterministic local setup verification;
- recomputes h from G and g;
- expensive O(N) structured work at install time.

V2 random linear setup check:

- transparent randomized local verification;
- field-size soundness error per round;
- practical default when combined with V0.

None of V0/V1/V2 alone proves dual-LPN hardness, malicious-server EMSM
security, side-channel resistance, Android security, or a production setup
ceremony.

