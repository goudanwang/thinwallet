# Phone Cost Model For P1/P2

Let:

- `N` be the private vector length used by a linear transform;
- `m` be the number of nonlinear multiplication constraints;
- `C_M(N)` be the cost of applying the public linear transform.

## P1

Phone online work:

```text
mask generation: O(N)
correction: C_M(N)
```

Communication:

```text
O(N) field elements for w_masked
```

If `C_M(N)` is O(N), O(N log N), or O(N^2), the phone correction follows that
same transform family.

## P2

Phone online work:

```text
O(m)
```

Communication:

```text
O(m) field elements
```

Preprocessing:

```text
m Beaver triples
```

P2 alone does not achieve phone-light private SNARK proving when `m` is large.

## Hybrid

Phone online work:

```text
O(m) + O(N) + C_M(N)
```

The toy experiment classifies this as blocked by phone-linear cost.
