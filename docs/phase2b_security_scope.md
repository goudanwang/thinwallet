# Phase 2B Security Scope

Implemented:

- paper-style t derivation;
- H1 support-leakage correction;
- H0 local persistent h file;
- mmap/positional h reads;
- h file digest verification;
- H0 support non-disclosure test;
- native Sumcheck proof compatibility with H0 EMSM;
- H2 library audit;
- negative-test inventory.

Not implemented:

- malicious-server EMSM check;
- Android device benchmark;
- production Rust h provider;
- private PIR/ORAM H2;
- verifier-side proof that `h = G^T g`;
- full setup ceremony.

Selected setup result:

```text
H_SETUP_SIGNED_PREVERIFIED
```

This means the client trusts a designated setup authority/preverified manifest
for global h correctness, while locally verifying it installed the expected h
file.

