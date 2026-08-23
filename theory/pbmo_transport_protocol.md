# PBMO Transport Protocol

Status: experiment-only protocol, version 1. This protocol moves the existing
masked PBMO scalar stream to a standalone server. It does not change field
arithmetic, mask derivation, correction, malicious checking, transcript order,
proof serialization, or verification.

## Security Scope

The selected scope is controlled authenticated plaintext TCP on a pinned
private-LAN endpoint. Every frame is authenticated with HMAC-SHA256 under a
32-byte experiment PSK. The PSK file is never archived; artifacts retain only
its SHA-256 key identifier. This prevents unauthenticated server substitution
and cross-protocol frame injection under the PSK assumption, but provides no
transport encryption and is not production channel security. PBMO masks hide
the private scalars from the server under the existing preprocessing model.

## State Machine

The client calls `reserve_session`, sends exactly one request header, sends
ordered chunks, sends one finish frame, and receives one response header plus
one response body. Abort is terminal. The server performs no MSM until the
header, all chunks, scalar count, row coverage, finish counts, and request
digest have been accepted.

The request header binds protocol and backend versions, curve, basis digest,
`q`, `m`, output count, token/session digest, workload, expected scalar and
chunk counts, body byte length, integrity mode, and nonce/challenge context.
The request digest hashes the canonical header payload followed by every
canonical chunk payload in order.

## Rejection Rules

The server rejects unsupported versions, backend/curve/basis mismatches,
incorrect dimensions or counts, invalid HMACs, wrong session digests,
duplicate/missing/reordered chunks, malformed or noncanonical scalars,
truncation, oversized frames, extra data, malformed finish frames, and aborted
sessions. The client rejects error frames, response-session/digest mismatches,
wrong lengths and malformed compressed Ristretto points.

## Privacy Boundary

The server receives only masked scalars and public request metadata. Structured
server logs contain timestamps, counts, digests, status, and buffer peaks, but
never witness values, masks, masked scalars, token seeds, or the PSK.

