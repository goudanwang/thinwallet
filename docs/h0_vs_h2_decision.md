# H0 vs H2 Decision

| Property | H0 local mmap h | H2 private retrieval |
| --- | --- | --- |
| Persistent client storage | Large: complete public h file | Low |
| Client RAM | Bounded by h batch and mmap residency | Depends on PIR implementation |
| Client computation | Sparse local reads and correction MSM | PIR query generation and decoding |
| Communication | No h network retrieval during proof | Query and response per batch |
| Server computation | No h lookup server involvement | PIR server computation over public database |
| Setup assumptions | Signed/preverified h manifest | PIR setup plus authenticated database |
| Support privacy | Strong against proving server via local access | Depends on PIR query privacy |
| Offline availability | Yes after installation | No, unless PIR server reachable |
| Mobile practicality | Storage-heavy but simple | Lower storage but higher protocol complexity |
| Implementation maturity | Implemented in Phase 2B | No auditable local PIR implementation found |

Decision: H0 is the Phase 2B primary path. H2 remains a future option only if a
single-server, authenticated, batch PIR implementation can be audited and
integrated.

