# Joint Credential Presentation

## Relation

A joint presentation proves a relation over an ordered vector
`Cred_0, ..., Cred_(k-1)` and one verifier session. Depending on policy, the
relation may include issuer authentication, commitment opening, common-holder
binding, selective disclosure, hidden equality classes, range and expiry
predicates, nonce/session binding, and policy-selected revocation predicates.

The verifier supplies policy, session and public registry state. It does not
select a concrete credential. The holder selects a canonical credential vector
whose records satisfy the policy.

## Revocation Set

`RevSet` is a subset of `{0, ..., k-1}` and `r = |RevSet|`. It is normalized to
ascending credential index before relation construction. Only `Cred_i` for
`i in RevSet` receives a revocation predicate. Each selected record has its own
revocation identifier, leaf/index and complete path, all bound to the
authenticated registry identifier, root and epoch. A path cannot be reassigned
to another credential merely because its sibling values happen to coincide in
an empty sparse subtree.

Credentials outside `RevSet` receive no revocation witness. Their policy may be
`None`, `ExpiryOnly`, or another externally specified policy. The current
authenticated in-circuit revocation implementation is `SparseMerkle`; no
accumulator support is claimed.

## Canonical Layout

Records are ordered by credential index. Within each credential, fields,
commitment-opening rows, holder rows, disclosures, equality classes, range
predicates and expiry predicates use the protocol-defined order. Revocation
rows follow ascending `RevSet`, then ascending path level. Public inputs,
witness variables, R1CS rows, and A/B/C entries use deterministic allocation
order; sparse entries are `(row,column,value)` ordered by matrix then row and
construction order. Hash-map order, filesystem order, worker schedule, chunk
size and store implementation are excluded from the layout.

The `relation_layout_digest` commits to the complete ordered A/B/C relation,
witness/public-input layout and padded dimensions. It is a layout identifier,
not a replacement for source authentication or proof soundness.
