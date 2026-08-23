# PBMO Wire Format v1

All integers are unsigned big-endian. Every TCP frame is:

| Field | Bytes | Meaning |
| --- | ---: | --- |
| magic | 8 | `TWPBMO1\\0` |
| version | 2 | wire version 1 |
| type | 1 | header/chunk/finish/response/error/abort |
| flags | 1 | zero in v1 |
| sequence | 4 | strict frame sequence |
| payload length | 4 | at most 1 MiB |
| session digest | 32 | request-scoped binding |
| HMAC-SHA256 | 32 | header fields plus payload |
| payload | variable | type-specific canonical payload |

The HMAC domain is `thinwallet/pbmo-wire-frame/v1` and covers magic, version,
type, flags, sequence, payload length, session digest, and payload.

## Request

The header payload length-prefixes strings and contains the complete fields in
`TransportRequestHeader`. A chunk contains `chunk_index`, `total_chunks`, row,
column start/end, scalar count, then canonical 32-byte Ristretto scalar
encodings. The finish payload contains chunk count, scalar count, and the
SHA-256 request digest.

## Response

The response header binds request digest, output count, response byte length,
and server validation/queue/MSM nanoseconds. The body is an ordered sequence of
canonical 32-byte compressed Ristretto points. Error payloads are bounded UTF-8
diagnostics and contain no secret values.

## Resource Bounds

Client serialization is one chunk plus one frame header, not a second `q*m`
vector. Socket timeouts and kernel buffers are bounded and reported. The v1
server retains received rows until finish validation, then computes ordered
MSMs; it records the largest single frame payload separately from retained
request state.

