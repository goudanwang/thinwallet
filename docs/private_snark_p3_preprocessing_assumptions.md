# P3 Preprocessing Assumptions

P3 must not treat preprocessing as free. The experiment separates three setup
models.

## P3-A: Phone-Generated Offline Preprocessing

The phone generates Beaver/VOLE-like correlations offline. The server receives
server-side shares and the phone keeps phone-side shares.

Advantages:

- No third-party dealer.
- The online interaction remains a phone plus single-server model.

Costs and limitations:

- Phone offline work is `O(number_of_multiplications)`.
- Phone storage is `O(number_of_multiplications)` for full triples.
- Online multiplication is still linear in the multiplication count.

At `m = 16384`, P3-A measured 43.305 ms of phone offline preprocessing and
1,572,864 bytes of phone triple storage.

## P3-B: Trusted Dealer / Issuer-Generated Preprocessing

An external dealer or issuer generates correlations and distributes shares.

Advantages:

- Phone offline generation can be low.
- Phone online behavior is unchanged from full triples.

Costs and limitations:

- This is no longer a pure two-party setup.
- The dealer or issuer becomes part of the trust and deployment model.
- Online multiplication is still linear in the multiplication count.

At `m = 16384`, P3-B measured 37.930 ms of dealer preprocessing and 1,572,864
bytes of phone triple storage.

## P3-C: Compressed Correlation Seeds

The experiment simulates short seeds that expand into many correlated triples.

Advantages:

- Before expansion, phone seed storage is 32 bytes in the toy model.
- It models the storage goal of a PCG/VOLE-style construction.

Costs and limitations:

- The implementation is not a secure PCG.
- It is marked `SIMULATED_PCG_NOT_SECURE`.
- After expansion, the phone still materializes `O(m)` triple shares in this
  toy implementation.
- Online multiplication is still linear in the multiplication count.

At `m = 16384`, P3-C measured 41.205 ms of simulated expansion, 32 bytes of
seed storage before expansion, and 1,572,864 bytes after expansion.
