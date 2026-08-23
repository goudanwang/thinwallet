# Related Work Matrix: Existing Work Gap Analysis

This matrix compares zkSNARK delegation, server-aided credential, mobile proving, and TEE-based proof delegation work against the target system defined in `docs/project_definition.md`.

"Single-server" means one administrative and trust domain, not necessarily one physical machine. Multiple internal CPUs, GPUs, machines, or workers are permitted, but security must not depend on non-collusion among them. If a system uses several workers or parties and relies on at least one worker or party not colluding, it is classified as a multi-party trust assumption.

This matrix distinguishes among: (1) possessing or deriving an application-level witness; (2) reducing it to a low-level or extended witness; and (3) simultaneously materializing the complete witness in client memory. These properties must not be treated as equivalent.

This matrix also distinguishes witness privacy, malicious-server soundness, and holder-authorized credential use. Witness privacy does not imply holder authorization. A protocol may hide the witness from a server while still lacking a mechanism that prevents the server from reusing credential-related state for a new verifier, nonce, predicate, or disclosure context.

| Work | Deployment / Trust Domain | Privacy Assumption | Malicious Server | Client Input | Client Generates Witness | Full Witness on Client | Client Computation | Client Memory | Communication | Outsourced Operations | Holder Authorization Binding | Prevents Independent Credential Use | Real Phone Evaluation | Main Limitation for Our Scenario |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Single-Server Private Outsourcing of zk-SNARKs | Single untrusted server / one trust domain | EMSM / LPN-style masking; client keeps witness/scalars private | Claims malicious-server support for outsourced MSM checks | Public instance and private witness/scalars for proving | The protocol assumes that the client possesses the private witness. Application-specific witness generation from compact input is outside the outsourcing protocol; the client executes the non-MSM prover operations locally. | The client owns the witness and executes the non-MSM portions of the prover. Whether the implementation requires the full witness to remain simultaneously materialized throughout proving is not established. | Field operations locally; MSM outsourced | Not optimized or evaluated as a primary contribution; client-side memory improvement is identified as future work | Not yet verified from the primary source. EMSM requires transmission of masked MSM inputs, but the exact end-to-end mobile communication cost must be measured. | Primarily MSM via EMSM; client does field operations locally | Not defined or enforced as part of the delegation protocol or its security model. | Not addressed for credentials | Not evaluated from available source | Closest single-domain EMSM baseline, but not end-to-end delegation of application-specific witness generation from compact credential state and not holder-authorized credential use |
| Server-Aided Anonymous Credentials | Issuer-operated or credential-system helper server. It is not a generic outsourced zkSNARK prover. | Helper protocol should be privacy-preserving/oblivious and unlinkable from later showings | Not directly comparable to malicious cloud-prover outsourcing | Holder credential, holder secrets/attributes, and helper-generated auxiliary information, rather than a generic zkSNARK witness-outsourcing interface | Not applicable as a generic zkSNARK witness-generation protocol | Not applicable as a generic zkSNARK proving protocol | Holder still runs credential Show using credential, attributes, predicate/nonce, and helper information | Not evaluated for zkSNARK prover memory | Helper interaction plus credential showing; not generic prover communication | Oblivious or privacy-preserving generation of fresh auxiliary information used by the holder during credential showing; not end-to-end outsourced SNARK proving | No explicit cloud-prover authorization abstraction matching our definition. The credential showing protocol may bind freshness information such as a nonce, but the helper is not acting as the holder's delegated presentation prover. | Not directly comparable. The helper does not receive the role of an end-to-end presentation prover and the holder still performs the Show algorithm using the credential and auxiliary information. | Not evaluated from available source | Credential-specific assistance rather than end-to-end delegation of witness generation and zkSNARK proof generation for a thin mobile wallet |
| Eos: Efficient Private Delegation of zkSNARK Provers | Multiple workers; privacy requires at least one non-colluding worker | Secret sharing of low-level witness across workers | Paper claims malicious-worker security; later DFS paper reports a security flaw requiring follow-up | Application/high-level witness reduced by delegator to low-level witness shares | Yes. The delegator performs witness reduction from the application-level or high-level witness to the low-level witness required by the proof system. | The delegator must produce or access the low-level witness, but the protocol supports streaming access and does not inherently require the full low-level witness to remain simultaneously materialized in memory. | Delegator remains online and participates in checks / protocol messages | Distinguish witness-generation space from delegation overhead: Eos does not eliminate memory needed to generate/access the initial witness, but claims constant additional memory beyond the initial witness-generation requirement when streaming access is available. | Per-worker communication includes secret shares and protocol messages | PIOP/PC prover computation across workers | Not defined or enforced as part of the delegation protocol or its security model. | Not addressed for credentials | Yes: Google Pixel 4a smartphone | Strong mobile delegation baseline, but it relies on multiple non-colluding workers and does not delegate application-specific witness generation from compact credential state. |
| Siniel | Several workers; privacy requires more than half honest and non-colluding | Secret sharing plus worker-side consistency checking | Claims malicious-worker security under honest-majority privacy assumption | Private witness plus authenticated shares and auxiliary checking data generated by delegator | The delegator is assumed to possess the private witness and generates authenticated witness shares and auxiliary checking data. Application-level witness generation from compact input is outside the Siniel protocol. | Unclear. The delegator processes the private witness to generate authenticated shares, but the paper does not establish that the complete witness must remain simultaneously materialized in client memory. | Offline sharing/authentication by delegator; after sending data, delegator can exit online proof generation | Not explicitly evaluated on phone; delegator resource profile is server-class in experiments | Communication remains important under low bandwidth | Entire zkSNARK computation after witness sharing | Not defined or enforced as part of the delegation protocol or its security model. | Not addressed for credentials | No; evaluation uses AWS/server-class delegator | Removes online interaction but still relies on multi-party trust and starts from a delegator-held private witness |
| zkSaaS: Zero-Knowledge SNARKs as a Service | Group of untrusted servers, including a large server; multi-party trust | Witness privacy is proved only against an honest majority of semi-honest servers | Proof soundness remains protected even if the proving servers are malicious. Witness privacy against malicious servers is conjectured or left without a formal proof. | Client statement and private input; client computes/shares extended witness | Yes. The client computes the satisfying assignment or extended witness and secret-shares it among the servers in the main construction. | The client computes and distributes the extended witness. The construction supports streaming to reduce peak memory, so complete simultaneous materialization is not necessarily required. | O(relation size) field work for witness expansion/share generation | Streaming reduces peak space while the client computes and shares the extended witness, but it does not remove the client's linear-scale witness-expansion and share-generation work. | One client-to-each-server round plus server interaction; extended witness shares sent | Distributed Groth16/Plonk proof generation after extended witness sharing | Not defined or enforced as part of the delegation protocol or its security model. | Not addressed for credentials | No; GCP/consumer-machine evaluation, not phone | Multi-server semi-honest privacy and client-side extended witness generation conflict with thin single-domain wallet target |
| DFS: Delegation-friendly zkSNARK and Private Delegation of Provers | Multiple independent parties / cloud platforms; nodes inside each party are same trust domain | Private delegation via secret sharing across independent non-colluding parties | Claims malicious security for DFS private delegation; analyzes selective-failure issue in prior work | Delegator-held witness distributed as shares to parties | The delegator is assumed to possess the witness and distribute witness shares. Application-specific witness generation from compact credential state is not delegated by DFS. | The protocol begins from a delegator-held witness, but whether the entire witness must be simultaneously materialized is not explicitly established. | Designed for low/logarithmic delegator workload after initial witness-share distribution | Low delegator memory is evaluated in a cluster setting with resource-limited nodes, not as mobile holder memory | DFS provides logarithmic delegator communication during the private proving protocol after the initial witness shares have been distributed. Distributing the witness shares remains linear in the witness size and is excluded from the reported proof-generation time. | New delegation-friendly SNARK and private delegation protocol | Not defined or enforced as part of the delegation protocol or its security model. | Not addressed for credentials | No real Android/iOS phone evaluation found | Valuable design direction, but relies on multiple independent trust domains, starts from a delegator-held witness, and does not include holder-specific presentation authorization |
| Mopro / mobile proving frameworks | Local mobile device; no cloud trust domain | No cloud privacy assumption; proofs generated locally | Not a delegation protocol | Circuit inputs, proving keys/artifacts, mobile app state | Yes, locally for supported backends | Yes, depending on backend/circuit | Local witness and proof generation on Android/iOS via Rust FFI | Local prover memory applies; depends on backend | Local only unless app adds networking | None; local proving framework | App-dependent, not framework-level holder authorization | Server cannot use credential because no server is involved | Supports real Android/iOS development; credential delegation not evaluated | Useful local-proving baseline and mobile integration layer, not privacy-preserving cloud delegation |
| TEE-based PPD design space / research prototypes | Design direction or research prototype rather than one uniform peer-reviewed system; usually one cloud provider with TEE/confidential VM | Privacy depends on attestation, hardware isolation, and side-channel assumptions | Depends on the concrete TEE threat model; denial of service and side channels remain concerns | Encrypted inputs or secrets delivered to an attested confidential component | Potentially no, if the confidential component performs witness generation | Not on phone if witness is generated inside TEE; full witness may exist inside the private boundary | Small client work possible after attestation/key agreement | Full-prover-in-TEE designs may expand the TCB and stress enclave/CVM memory | Request plus encrypted inputs/results; exact cost design-specific | Potentially full prover, private witness component, or key-recovery component; external accelerator use is design-specific | Unclear; TEE does not automatically provide holder authorization | Unclear unless holder authorization is explicitly integrated | Not evaluated from available source | Candidate implementation path, not a final design; TEE changes the confidential boundary rather than automatically solving holder-authorized delegated proving |

## 1. Verified Gaps

* Multi-worker private delegation systems such as Eos, Siniel, zkSaaS, and DFS do not match a single administrative trust domain when their privacy requires non-collusion among workers or parties.
* Eos, Siniel, zkSaaS, and DFS begin their delegation protocols from a delegator-held low-level witness, satisfying assignment, or extended witness. They do not provide a general mechanism for privately delegating application-specific witness generation from compact credential state.
* zkSaaS explicitly treats faster extended-witness generation as outside its main construction.
* Single-Server Private Outsourcing primarily outsources MSM and leaves field operations on the client, so it is an EMSM-style baseline rather than full end-to-end delegation from compact credential state.
* None of the reviewed generic zkSNARK delegation systems defines holder-authorized presentation as an explicit delegation property or security goal.
* Mopro is a mobile proving framework for local proving, not a privacy-preserving delegation protocol.
* Server-Aided Anonymous Credentials is a credential-specific helper protocol, not generic end-to-end SNARK witness generation and proof outsourcing.
* TEE-based PPD is a candidate confidential execution boundary and does not automatically provide holder authorization.

## 2. Unverified Hypotheses

The following claims require reproduction, implementation, or mobile experiments before being used as project claims:

* Whether MSM outsourcing leaves witness generation, field computation, communication, or memory as the dominant mobile bottleneck for credential presentation circuits.
* Whether a mobile wallet would hit peak RSS limits when holding the witness, extended witness, proving key, or multiple linear-size prover vectors.
* Whether any specific existing delegation protocol requires the complete witness to be simultaneously materialized in client memory for credential workloads.
* Whether client memory is linear for a specific credential workload after streaming optimizations are applied.
* Whether memory is the dominant bottleneck compared with witness generation, field computation, communication, energy, or latency.
* Whether masked scalar upload in EMSM-style outsourcing is too large for realistic mobile credential presentations.
* The actual share of time and energy spent in witness generation versus proof generation on Android phones.
* Whether credential-specific witness generation can be streamed or split without leaking hidden attributes to the untrusted host/accelerator.
* Whether a TEE/private component can handle credential recovery and witness generation without becoming an impractically large TCB.

## 3. Closest Competitors

### Single-Server Private Outsourcing of zk-SNARKs

Common point: It directly addresses private outsourcing to one untrusted server and is the closest single-domain proving baseline.

Key difference: The available evidence indicates that it outsources MSM while the client performs field operations locally; it does not start from compact credential state or include holder-authorized credential use.

Baseline/comparison: Implement or compare against an EMSM-style Groth16 baseline, measuring client field work, scalar upload, memory, latency, and energy.

### Eos

Common point: It targets resource-constrained delegators and includes a real smartphone evaluation.

Key difference: It depends on multiple workers with a non-collusion assumption and requires the delegator to perform witness reduction and share the low-level witness.

Baseline/comparison: Use as a mobile delegation reference for latency, active computation, and memory, while separating its multi-worker trust assumption from our single-domain target.

### zkSaaS

Common point: It outsources zkSNARK proving after the witness/extended witness is prepared and focuses on reducing client work after sharing.

Key difference: It relies on multiple semi-honest servers for privacy and assumes client-side extended witness generation in the main construction.

Baseline/comparison: Use for multi-server proof-generation outsourcing after extended-witness sharing, not as a direct credential-wallet baseline.

### Server-Aided Anonymous Credentials

Common point: It is relevant to credential-system security goals because it studies server assistance while preserving anonymous-credential privacy.

Key difference: It is not a generic proving architecture baseline. The helper generates fresh auxiliary credential information, while the holder still performs credential showing.

Baseline/comparison: Use as a security-goal comparison for credential helper roles and unlinkability, not as a computational baseline for delegated zkSNARK proving.

### DFS

Common point: It explicitly studies delegation-friendly SNARK design, malicious security, communication, and scalable private delegation.

Key difference: It relies on multiple independent parties/cloud platforms and a different proof-system design rather than a single administrative trust domain.

Baseline/comparison: Compare design ideas around witness-dependent phases and communication, but treat it as a multi-party proof-backend competitor rather than a single-server deployment.

### Mopro

Common point: It is directly relevant for real mobile proving infrastructure and Android/iOS integration.

Key difference: It is local proving tooling, not a cloud delegation protocol.

Baseline/comparison: Use as a local mobile proving baseline or implementation substrate for Android measurements.

## 4. Tentative Novelty Boundary

The candidate novelty boundary is the combination of:

1. end-to-end delegation beginning from compact credential state rather than an already-materialized witness;
2. a single administrative and trust domain;
3. holder authorization for every presentation context;
4. a thin mobile client; and
5. real phone evaluation.

This novelty boundary remains subject to further related-work study and must not be described as "the first" without stronger evidence.

## Matrix Status

This matrix is an evidence-oriented working document. Entries marked as unknown, unclear, or not evaluated require additional source inspection or reproduction before being used as definitive novelty or performance claims.
