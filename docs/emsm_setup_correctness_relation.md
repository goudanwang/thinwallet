# EMSM Setup Correctness Relation

Public inputs:

- RAA generator `G`;
- basis vector `g = (g_0, ..., g_{n-1})`;
- correction vector `h = (h_0, ..., h_{N-1})`;
- parameter manifest;
- `root_g`;
- `root_h`.

Relation:

```text
h = G^T g
```

where `G in F^{n x N}`, `g in Group^n`, `h in Group^N`, and `N = 4n`.

If h is incorrect, EMSM decryption can return a wrong MSM result, native proof
assembly can fail, a prover can suffer denial of service, and stronger
malicious models may face selective-failure concerns.

