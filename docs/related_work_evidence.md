# Related Work Evidence Log

This file records evidence used for `docs/related_work_matrix.md`. It intentionally avoids unverified claims, invented page numbers, and blog-only conclusions for core technical facts.

## Single-Server Private Outsourcing of zk-SNARKs

* Full title: Single-Server Private Outsourcing of zk-SNARKs
* Authors: Kasra Abbaszadeh, Hossein Hafezi, Jonathan Katz, Sarah Meiklejohn
* Venue / year: IEEE Symposium on Security and Privacy 2026
* Primary source: [IEEE S&P 2026 accepted papers page](https://sp2026.ieee-security.org/accepted-papers.html), [IACR ePrint 2025/2113](https://eprint.iacr.org/2025/2113), [author publication page](https://hosseinhafezi.com/publication.html), [ZKProof8 slides](https://hosseinhafezi.com/asset/Server-aided%20(ZKProofs8).pdf)
* Relevant sections or pages: IEEE S&P accepted-papers entry; ePrint record and abstract; author publication entry; ZKProof8 slides. Full-paper section extraction pending for the server-aided prover interface, EMSM construction, EMSM client inputs and outputs, malicious-server check, Nova/Groth16/Plonk client/server partitioning, communication complexity, experimental client hardware, and the concrete location of memory-related future work.
* Deployment / trust model: The title and slides identify a single-server private outsourcing model. This is aligned with a single administrative/trust-domain baseline.
* Delegator input: Public instance and private witness/scalars for proving. The protocol assumes that the client possesses the private witness.
* Witness responsibilities: Application-specific witness generation from compact input is outside the outsourcing protocol. Slides state that the prover performs field operations locally and outsources MSMs. The client owns the witness and executes the non-MSM portions of the prover.
* Memory / streaming: Whether the implementation requires the full witness to remain simultaneously materialized throughout proving is not established from the accessible primary material. Client-side memory improvement is identified as future work in the available slides and should not be treated as an evaluated contribution.
* Malicious security: Slides describe EMSM using a Dual-LPN/RAA-code style construction and a client-side malicious-server check for outsourced MSM. The scheme claims malicious-server security for outsourced MSM. The exact assumptions, verification equations, failure probability, and composition with each supported SNARK remain to be extracted from the full paper.
* Mobile evaluation: Not evaluated from available source. The slides report server-aided Nova and Groth16 speedups but do not show a real Android/iOS experiment.
* Holder-authorization relevance: Not defined or enforced as part of the delegation protocol or its security model. This does not imply that an application circuit could never include an authorization check; rather, holder-controlled presentation semantics are not defined as a delegation-level security property.
* Unresolved questions: Full-paper extraction is still required for the formal server-aided prover interface, EMSM client inputs and outputs, client-side residual field operations, malicious-server verification equation, communication complexity, client experimental hardware, and the section/page that discusses memory future work. Until those are extracted, this evidence log should not be used to claim that EMSM communication has a specific asymptotic or byte cost, that the client must keep the complete witness materialized, that memory is the dominant bottleneck, or that the scheme is unusable on phones.

## Server-Aided Anonymous Credentials

* Full title: Server-Aided Anonymous Credentials
* Authors: Rutchathon Chairattana-Apirom, Franklin Harding, Anna Lysyanskaya, Stefano Tessaro
* Venue / year: CRYPTO 2025
* Primary source: [IACR ePrint 2025/513](https://eprint.iacr.org/2025/513), [Springer CRYPTO 2025 chapter page](https://link.springer.com/chapter/10.1007/978-3-032-01887-8_10)
* Relevant sections or pages: Springer CRYPTO 2025 chapter metadata, pp. 291-324; ePrint full paper abstract and protocol discussion.
* Deployment / trust model: The holder obtains fresh auxiliary information through an earlier privacy-preserving interaction associated with the credential system or issuer. The holder later uses this information when running the credential Show algorithm. The helper is not a delegated end-to-end prover and should not be described as a cloud server that long-term holds the credential and proves on the holder's behalf.
* Delegator input: Holder credential, holder secrets/attributes, freshness or presentation context, and helper-generated auxiliary information.
* Witness responsibilities: Not applicable as a generic zkSNARK witness-generation protocol. The holder still runs the credential Show algorithm using the credential, attributes/secrets, predicate or disclosed-message context, freshness information such as a nonce, and fresh auxiliary information obtained through the helper protocol.
* Memory / streaming: Not evaluated for zkSNARK prover memory or witness streaming.
* Malicious security: The helper generates fresh auxiliary information in an oblivious or privacy-preserving way. The paper's goal includes preventing the helper from learning holder attributes and preventing helper interactions from being linkable to later showing interactions. This is credential-specific assistance and privacy, not generic zkSNARK delegation or generic SNARK witness privacy.
* Mobile evaluation: Not evaluated from available source.
* Holder-authorization relevance: There is no explicit cloud-prover authorization abstraction matching this project's definition. A credential showing may bind freshness information such as a nonce, but the helper is not acting as the holder's delegated end-to-end presentation prover.
* Unresolved questions: Whether the scheme can be combined with zkSNARK-based credential presentations; whether its auxiliary-information generation can reduce mobile proving work; whether it can be adapted to request-bound holder authorization for a delegated prover.

## Eos: Efficient Private Delegation of zkSNARK Provers

* Full title: Eos: Efficient Private Delegation of zkSNARK Provers
* Authors: Alessandro Chiesa, Ryan Lehmkuhl, Pratyush Mishra, Yinuo Zhang
* Venue / year: USENIX Security 2023
* Primary source: [USENIX page](https://www.usenix.org/conference/usenixsecurity23/presentation/chiesa), [USENIX PDF](https://www.usenix.org/system/files/usenixsecurity23-chiesa.pdf)
* Relevant sections or pages: Abstract, p. 1; Section 2 construction overview and Remark 2.1 on witness reduction, p. 3; Section 7.2 memory optimization, p. 10; Section 8 evaluation setup, p. 11
* Deployment / trust model: The paper delegates proof generation to a set of workers. The abstract and construction overview state privacy if at least one worker does not collude with the others.
* Delegator input: Application-level or high-level witness that the delegator reduces to a low-level witness, plus public input.
* Witness responsibilities: Remark 2.1 says the delegator performs witness reduction and secret-shares the resulting low-level witness among workers. The construction overview states that the delegator sends public input and secret shares of the large private witness to workers.
* Memory / streaming: Section 7.2 states that Eos can process the delegator-side material in batches and use constant additional memory beyond what is required to produce the initial witness, so the protocol should not be described as inherently requiring the full low-level witness to remain simultaneously materialized in memory.
* Malicious security: The paper claims security against malicious workers under the non-collusion assumption. DFS later reports a flaw in prior Eos malicious-security guarantees; specifically, DFS Section 2.4, "Private delegation for DFS" (official PDF pp. 7-8), discusses unauthenticated opening values in Eos and a selective-failure attack that can leak information. This requires follow-up before relying on Eos as malicious-secure.
* Mobile evaluation: Yes. Section 8 evaluates a Google Pixel 4a smartphone with 6 GB RAM and Snapdragon 730G, interacting with AWS worker machines.
* Holder-authorization relevance: Not defined or enforced as part of the delegation protocol or its security model. This does not imply that an application circuit could never include an authorization check; rather, holder-controlled presentation semantics are not defined as a delegation-level security property.
* Unresolved questions: How Eos behaves for credential-specific circuits and witness-generation pipelines; whether the Pixel 4a measurements include energy or thermal behavior; how much mobile memory is required for application-level witness generation before Eos streaming/delegation begins.

## Siniel

* Full title: Siniel: Distributed Privacy-Preserving zkSNARK
* Authors: Yunbo Yang, Yuejia Cheng, Kailun Wang, Xiaoguo Li, Jianfei Sun, Jiachen Shen, Xiaolei Dong, Zhenfu Cao, Guomin Yang, Robert H. Deng
* Venue / year: NDSS 2025
* Primary source: [NDSS paper page](https://www.ndss-symposium.org/ndss-paper/siniel-distributed-privacy-preserving-zksnark/), [NDSS PDF](https://www.ndss-symposium.org/wp-content/uploads/2025-152-paper.pdf)
* Relevant sections or pages: Abstract, p. 1; Section I introduction, pp. 1-3; Section III overview and security model, pp. 4-8; Section V implementation and evaluation, p. 13; security proof discussion, p. 15
* Deployment / trust model: Siniel delegates to several workers. The overview states that the delegator sends shares of the private witness and workers perform online proof generation without further delegator interaction.
* Delegator input: Private witness held by the delegator.
* Witness responsibilities: The delegator is assumed to possess the private witness. In the offline phase, it generates authenticated witness shares and auxiliary checking data such as authentication tags/keys before outsourcing. Application-level witness generation from compact input is outside the Siniel protocol.
* Memory / streaming: Unclear. The delegator processes the private witness to generate authenticated shares, but the paper does not establish that the complete witness must remain simultaneously materialized in client memory.
* Malicious security: The paper states that the private witness is hidden from all workers if more than half are honest and do not collude. It claims malicious-worker security under that assumption.
* Mobile evaluation: No real phone evaluation found. The evaluation section uses an AWS c5a.4xlarge instance as the delegator and server-class workers.
* Holder-authorization relevance: Not defined or enforced as part of the delegation protocol or its security model. This does not imply that an application circuit could never include an authorization check; rather, holder-controlled presentation semantics are not defined as a delegation-level security property.
* Unresolved questions: Cost of application-level witness generation before sharing; whether the complete witness must remain simultaneously materialized while generating authenticated shares; whether the scheme can be adapted to one administrative trust domain; mobile peak memory and energy; whether low-bandwidth communication is practical for mobile credential presentations.

## zkSaaS

* Full title: zkSaaS: Zero-Knowledge SNARKs as a Service
* Authors: Sanjam Garg, Aarushi Goel, Abhishek Jain, Guru-Vamsi Policharla, Sruthi Sekar
* Venue / year: USENIX Security 2023
* Primary source: [USENIX page](https://www.usenix.org/conference/usenixsecurity23/presentation/garg), [USENIX PDF](https://www.usenix.org/system/files/usenixsecurity23-garg.pdf), [NSF/PAR PDF copy](https://par.nsf.gov/servlets/purl/10540686)
* Relevant sections or pages: Abstract; Section 1.1 contributions and security discussion; Section 2 framework; Section 3 proof-generation discussion; Section 7 implementation and evaluation
* Deployment / trust model: The paper outsources proof generation to a group of untrusted servers. It also introduces a large server in a star-like topology.
* Delegator input: Statement and private input/witness from which the client computes the satisfying assignment or extended witness.
* Witness responsibilities: The paper states that proof generation first extends a short witness into an extended witness/satisfying assignment, and that the client computes and shares this extended witness in the main construction.
* Memory / streaming: Streaming reduces peak space while the client computes and shares the extended witness, but it does not remove the linear-scale witness-expansion and share-generation work.
* Malicious security: Proof soundness remains protected even if the proving servers are malicious. Witness privacy is proved only against an honest majority of semi-honest servers. Privacy against malicious servers is conjectured or left without a formal proof in the paper's security discussion.
* Mobile evaluation: No real phone evaluation found. Experiments use GCP machines and a consumer-machine baseline.
* Holder-authorization relevance: Not defined or enforced as part of the delegation protocol or its security model. This does not imply that an application circuit could never include an authorization check; rather, holder-controlled presentation semantics are not defined as a delegation-level security property.
* Unresolved questions: Practical client cost for credential witness generation; amount of mobile memory needed for streaming extended-witness generation; energy and thermal impact on phones; whether malicious privacy can be added efficiently.

## DFS / Delegation-Friendly zkSNARK

* Full title: DFS: Delegation-friendly zkSNARK and Private Delegation of Provers
* Authors: Yuncong Hu, Pratyush Mishra, Xiao Wang, Jie Xie, Kang Yang, Yu Yu, Yuwen Zhang
* Venue / year: USENIX Security 2025
* Primary source: [USENIX page](https://www.usenix.org/conference/usenixsecurity25/presentation/hu-yuncong), [USENIX PDF](https://www.usenix.org/system/files/usenixsecurity25-hu-yuncong.pdf), [USENIX appendix PDF](https://www.usenix.org/system/files/usenixsecurity25-appendix-hu-yuncong.pdf)
* Relevant sections or pages: Abstract, p. 1; Section 1 introduction, pp. 1-2; Section 2 overview and threat model, p. 3; Section 2.4 discussion of Eos unauthenticated opening values and selective-failure attack, PDF pp. 7-8; Section 7 evaluation
* Deployment / trust model: DFS private delegation uses multiple independent parties/cloud platforms. The paper explicitly treats nodes inside one party as the same trust domain and says nodes within a party should not be counted as independent trust parties.
* Delegator input: Witness held by the delegator and distributed as shares to parties.
* Witness responsibilities: The delegator is assumed to possess the witness and distribute witness shares to parties. Application-specific witness generation from compact credential state is not delegated by DFS.
* Memory / streaming: The protocol begins from a delegator-held witness, but whether the entire witness must be simultaneously materialized by the delegator is not explicitly established. Low delegator memory is evaluated in a cluster setting with resource-limited nodes, not as mobile holder memory.
* Malicious security: Privacy depends on non-collusion among independent parties; the paper claims malicious security for its private delegation and discusses selective-failure issues in prior work.
* Mobile evaluation: No real Android/iOS evaluation found in the paper.
* Holder-authorization relevance: Not defined or enforced as part of the delegation protocol or its security model. This does not imply that an application circuit could never include an authorization check; rather, holder-controlled presentation semantics are not defined as a delegation-level security property.
* Unresolved questions: Whether DFS ideas can be adapted to Groth16 credential circuits; whether a single-domain variant is possible without losing witness privacy; whether the entire witness must be simultaneously materialized by the delegator; mobile cost of witness sharing and credential-specific witness generation.
* Additional communication note: DFS reports logarithmic delegator communication for the private proving protocol after witness shares have been distributed. The paper's threat-model/overview starts from a delegator-held witness that is shared among parties. The initial distribution of witness shares incurs per-delegation communication proportional to the witness-share data and is outside the online proof-generation communication reported by DFS. This distribution cost should not be counted as eliminated by the logarithmic proof-generation communication claim.

## Mopro / Mobile Proving Frameworks

* Full title: Mopro: mobile proving framework
* Authors: zkmopro project contributors
* Venue / year: Official open-source project documentation, active project
* Primary source: [Mopro GitHub repository](https://github.com/zkmopro/mopro), [Mopro documentation](https://zkmopro.org/docs/intro), [Mopro performance documentation](https://zkmopro.org/docs/performance). Accessed: June 29, 2026.
* Relevant sections or pages: Project README; documentation introduction; performance documentation. Accessed: June 29, 2026.
* Evidence status: Mopro is an actively evolving project. Claims about native witness and proof generation refer to the currently inspected documentation and should be associated with an access date or release.
* Deployment / trust model: Local mobile proving framework for Android/iOS integration, not a delegation protocol.
* Delegator input: Local circuit inputs, proving artifacts, and mobile app state.
* Witness responsibilities: The mobile app performs local witness/proof generation for supported backends and circuits.
* Memory / streaming: Local prover memory depends on backend, circuit, and app integration.
* Malicious security: No cloud privacy assumption because the framework is local by default. Any networked delegation protocol would need to be added separately.
* Mobile evaluation: The project is directly about mobile proving and supports real mobile platforms. It does not provide a credential-specific private cloud delegation evaluation for this project scenario.
* Holder-authorization relevance: Holder authorization is app/protocol logic, not provided as a delegation-security abstraction by the framework.
* Unresolved questions: Which backend gives the most realistic local Groth16 credential baseline; whether Mopro measures witness generation separately from proof generation for the target circuit; peak RSS and energy on the target Android phones.

## Candidate Implementation Approaches

### TEE-Based Private Proof Delegation Design Space / Research Prototypes

* Full title: TEE based private proof delegation
* Authors: Takamichi Tsutsumi / Privacy Stewards of Ethereum
* Venue / year: PSE technical article, 2025; design direction or research prototype rather than one uniform peer-reviewed system
* Primary source: [PSE article](https://pse.dev/blog/tee-based-ppd), [GitHub source link exposed by the article page](https://github.com/privacy-ethereum/website-v2/blob/main/content/articles/tee-based-ppd.md), [Phala Cloud TEE/ZK case documentation](https://docs.phala.com/phala-cloud/cases/tee_with_zk_and_zkrollup)
* Relevant sections or pages: PSE article introduction and appendix on process-based vs VM-based TEEs; Phala Cloud TEE/ZK use-case documentation
* Evidence status: The PSE source is a research/design article rather than a peer-reviewed system paper. Phala documentation is used only as an implementation example and not as evidence of a formally analyzed private proof delegation protocol.
* Deployment / trust model: Usually a single cloud provider running proof generation inside a TEE or confidential VM, with remote attestation used to identify the protected environment.
* Delegator input: Design-specific encrypted inputs or secrets delivered to an attested confidential component.
* Witness responsibilities: Design-specific. A confidential component may perform witness generation, full proving, or only part of the private computation.
* Memory / streaming: Enclave/CVM memory and TCB size are design-specific concerns; putting the full prover inside TEE may increase both.
* Malicious security: TEE changes the confidential boundary; privacy depends on attestation, hardware isolation, and side-channel assumptions. The untrusted host/hypervisor is outside the trusted boundary, but side channels, denial of service, and TCB size remain concerns.
* Mobile evaluation: Not evaluated from available source for mobile credential wallets.
* Holder-authorization relevance: Not inherent. TEE does not automatically provide holder authorization; request semantics must be explicitly bound and enforced inside or around the confidential component.
* Unresolved questions: Whether to place full proving, only witness generation, or only key recovery inside the private component; enclave/CVM memory requirements; whether putting the entire prover inside TEE would make the TCB too large; whether external accelerator use is possible without exposing witness data; how to bind attestation, request semantics, and proof output.

## Evidence Status

This evidence log is suitable for guiding system design and baseline selection. Bibliographic metadata has been checked against official sources. Claims about Single-Server Private Outsourcing still require full-paper section extraction before they are used as definitive novelty, complexity, or performance claims.

## Questions Requiring Reproduction

* For Single-Server Private Outsourcing, how much mobile work remains after EMSM for a concrete Groth16 credential circuit?
* Does EMSM-style outsourcing require uploading large masked scalar vectors, and how does that affect mobile latency and energy?
* What is the peak RSS on Android for local Groth16 credential proving, separated into witness generation, extended-witness generation, proving-key loading, FFT/NTT, and MSM?
* Can witness generation from compact credential state be performed in a private component without materializing the full witness on the phone?
* Can a holder authorization be implemented so that the server may retry the same presentation but cannot change verifier, nonce, predicate, disclosure set, credential reference, or protocol context?
* How much state must a server retain to support fault recovery, and can that state be made non-transferable across requests?
* For TEE or confidential-VM designs, what is the smallest private computation boundary that still protects undisclosed credential attributes?
* Which Mopro backend and mobile platform should be used as the local proving baseline for `age >= 18` credential presentation?
* Can an EMSM baseline, plain cloud proving baseline, and local proving baseline all be implemented with the same circuit and measurement harness?
