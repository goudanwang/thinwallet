# Phase V4 Network Profiles Plan

Network evaluation should preserve the Phase V2 PBMO message sequence while
injecting reproducible bandwidth, latency, jitter, loss, disconnect, and
retry profiles. Report client masking, upload, server MSM, download, recovery,
batch checking, and total latency separately.

Profiles should cover local Wi-Fi, stable broadband, constrained cellular,
high-latency cellular, and interrupted sessions. Token reservation and
consumption semantics must remain crash-safe under retries; no profile may
reuse a spent token or conceal server failure inside prover time.
