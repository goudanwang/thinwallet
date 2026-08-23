# H Support Leakage Attack

Corrected status:

```text
H1_DIRECT_SPARSE_H_QUERY_INSECURE
REMOTE_H_SUPPORT_LEAKAGE_NOT_ACCEPTABLE
MALICIOUS_EMSM_DEFERRED_UNTIL_H_PRIVACY_SOLVED
```

In H1, the client asks the proving server for the h entries indexed by
`S = supp(e)`. This reveals the sparse-noise support.

The masked vector is:

```text
v = z + G_S e_S
```

If the server learns `S`, then for any vector `a` satisfying:

```text
a^T G_S = 0
```

the server obtains:

```text
a^T v = a^T z
```

Therefore H1 cannot be used for witness-privacy claims. Phase 2B replaces H1
with H0 local h access as the primary practical baseline.

