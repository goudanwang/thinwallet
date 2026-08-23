# H0 Setup Trust Model

Selected Phase 2B setup result:

```text
H_SETUP_SIGNED_PREVERIFIED
```

The h file is public setup data. Phase 2B authenticates the installed h file by
manifest digests and models a designated setup authority signature over the
preverified manifest.

Trust boundary:

- the client verifies it installed the authenticated h file;
- local mmap access prevents the proving server from observing `support(e)`;
- Phase 2B does not make the verifier rederive or prove `h = G^T g`;
- setup-authority correctness remains part of the trusted/preverified setup
  assumption.

