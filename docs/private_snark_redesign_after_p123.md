# Proof-System Redesign After P1/P2/P3

Status marker:

```text
P123_BLOCKER_DOCUMENTED
```

## P1 Conclusion

Masked linear offload is correct but phone correction remains proportional to
the linear transform cost.

## P2 Conclusion

Client-assisted multiplication is correct but phone online work and
communication remain linear in the number of nonlinear multiplications.

## P3 Conclusion

Correlation-assisted preprocessing did not improve online phone cost in the
current toy model and introduces storage/setup assumptions.

## Therefore

The main blocker is not merely outsourcing MSM/FFT.
The main blocker is private nonlinear witness computation.

The new mainline should stop micro-tuning P1/P2/P3 and ask whether a proof
system can be designed or selected so that:

- the phone handles only a small private nonlinear core;
- the server handles large public, linear, or algebraic prover work;
- the server does not learn the private witness;
- the verifier does not trust the server;
- final verification remains standard or explicitly specified.

This is not arbitrary R1CS private proving with phone O(1). It is a search for
restricted or redesigned proof systems for phone-light private proving.

## Informal Blocker Observation

```text
INFORMAL_BLOCKER_OBSERVATION
NOT_A_FORMAL_LOWER_BOUND
```

If a circuit contains `M` independent private-private multiplications that are
request-dependent and not preprocessed, then a single semi-honest server cannot
compute them from a simple masked witness without either:

1. learning private information;
2. interacting with the phone `O(M)` times or exchanging `O(M)` data;
3. relying on `O(M)` preprocessing correlations;
4. changing the proof system or circuit class.

This is an informal blocker observation, not a proved lower bound.
