# Linear Vs Nonlinear Boundary

The experiment confirms the expected boundary:

- linear transforms can be masked and offloaded to the server;
- nonlinear multiplication requires interaction, preprocessing, or a different
  proof-system design;
- correcting masked linear output can itself cost O(N) or O(N log N) on the
  phone.

## P1 Boundary

P1 works algebraically because:

```text
M(w + r) - M(r) = M(w)
```

The privacy story is straightforward for semi-honest linear transforms, but the
phone still computes `M(r)`.

## P2 Boundary

P2 handles:

```text
c = a * b
```

over additive shares using Beaver triples. This protects the private values in
the toy semi-honest model, but every multiplication consumes one triple and
requires online phone work and communication.

## Hybrid Boundary

The hybrid toy pipeline is correct, but it inherits both costs:

- O(m) phone work and communication for nonlinear multiplications;
- O(N) or O(N log N) phone correction for masked linear transforms.
