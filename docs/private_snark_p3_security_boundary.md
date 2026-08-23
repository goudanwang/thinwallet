# P3 Security Boundary

This experiment does not prove real VOLE/PCG security.

Full triples are information-theoretic only under trusted preprocessing.
Simulated compressed correlations are not secure.
Malicious server security is not implemented.
This experiment only evaluates whether correlation-assisted preprocessing could
change the phone online cost profile.

## Boundary Questions

Does the server see the witness in the clear?

No in the toy sharing model. The server receives additive shares and opened
differences `d = a - u`, `e = b - v`, not the raw witness values. This is only
semi-honest reasoning and is not a malicious-server proof.

Is phone online lower than P2?

No in the measured toy model. At `m = 16384`, P2 phone online was 12.576 ms,
while P3-A was 13.644 ms, P3-B was 19.082 ms, and P3-C simulated was 13.753 ms.

Does phone offline become heavier?

Yes for P3-A. At `m = 16384`, phone-generated preprocessing measured 43.305 ms
and required 1,572,864 bytes of phone triple storage.

Is a third-party dealer required?

Only for P3-B. That mode emits `P3_REQUIRES_TRUSTED_PREPROCESSING` and is not a
pure two-party setup model.

Is it still a single-server model?

P3-A and P3-C preserve a pure phone plus single-server online model in the toy
experiment. P3-B preserves a single server online, but adds trusted
preprocessing outside the pure two-party model.

Can the experiment output a standard SNARK proof?

No. It only evaluates toy private multiplication and a toy masked-linear hybrid
pipeline. It does not assemble or verify a standard SNARK proof.

Does preprocessing need to be integrated with a proof-system-specific prover?

Yes for any real protocol. The toy experiment stops at shared witness-layer
multiplication and linear transform costs. It does not show how the resulting
state becomes a publicly verifiable proof without additional proof-system
integration.
