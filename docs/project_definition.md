# Project Definition: User-Controlled Single-Server Private zkSNARK Delegation for Mobile Credential Wallets

## 1. Research Context

Mobile credential wallets can use zkSNARKs to support privacy-preserving credential presentations. In this setting, a holder may prove selective disclosure claims, predicate statements over credential attributes, and proof of possession without revealing the full credential or all hidden attributes.

For complex credential presentation workloads, witness generation and zkSNARK proof generation may impose pressure on mobile devices in terms of computation, memory, storage, energy consumption, and end-to-end latency. This is a research hypothesis that must be validated through real experiments. The project should not assume that all phones are unable to perform local proving; instead, it should measure when and how local proving becomes costly for realistic wallet workloads and device classes.

The system goal is to keep the mobile wallet responsible for only a small amount of online work while delegating as much proof computation as possible to a cloud service.

## 2. Deployment Motivation

This project studies a single-server deployment model because practical wallet backends are often operated by one company or one administrative domain. In such deployments, multiple workers under the same operator may improve throughput and availability, but they do not provide an independent trust basis for cryptographic non-collusion.

Deploying multiple workers under one administrative domain does not justify a non-collusion assumption, while involving multiple independent providers introduces substantial operational and economic complexity.

Using multiple independent service providers may also complicate deployment, governance, cost allocation, accountability, service-level agreements, incident response, and liability boundaries. A single-server model therefore better matches the deployment constraints that many real wallet operators are likely to face.

## 3. Problem Statement

The target proving workflow is:

```text
compact mobile credential state
-> witness generation
-> zkSNARK proof generation
-> presentation verification
```

Existing single-server outsourcing approaches may primarily optimize local proving operators such as multi-scalar multiplication (MSM), while leaving substantial end-to-end work on the delegating mobile wallet. In particular, they may still require the delegator to generate the complete witness, execute witness-dependent field computation, store prover state that grows linearly with the circuit size or witness size, or upload large volumes of scalar data to the server.

These limitations are working hypotheses, not established conclusions for all systems. The project must verify them experimentally and analytically against concrete proving systems, circuits, credential presentation workloads, and mobile device profiles.

## 4. Core Research Question

How can a resource-constrained mobile credential wallet delegate end-to-end zkSNARK proving to a single potentially malicious cloud service, while minimizing mobile computation, memory, and storage, preserving credential privacy, and preventing the service from independently using the holder's credential?

Subquestions:

1. How can witness generation be delegated, rather than only MSM?
2. How can the phone avoid materializing the full witness, extended witness, proving key, and large buffers?
3. How can a single malicious server be prevented from learning the credential and hidden attributes?
4. How can the protocol ensure that the server must obtain user authorization for the current presentation request?

## 5. Central Security Insight

The server may obtain proving capability, but must not obtain credential-use capability.

The tentative term for this property is "Holder-Authorized Delegated Proving".

Intuitively, Holder-Authorized Delegated Proving means that even if the server stores credential ciphertexts, proving keys, server-side state, past authorizations, and past proofs, it cannot generate a valid presentation for a current request without fresh authorization from the phone for that specific request.

A holder authorization permits proof generation only for the exact authorized request semantics. The server may retry proof generation or produce multiple randomized proofs for the same request when needed for fault recovery, but the authorization must not be transferable to a different verifier, nonce, predicate, disclosure set, credential reference, or protocol context.

This definition will later need to be formalized as a security game.

## 6. Target System Properties

The following properties are design objectives for the target system, not claims about an already implemented protocol.

### 6.1 Thin Mobile Client

The mobile wallet is intended to execute only a small amount of online work, including:

* parsing and displaying the presentation request;
* obtaining user confirmation;
* producing one small-scale holder authorization;
* performing necessary encryption or key agreement;
* performing final proof verification or result confirmation.

As a design objective, the mobile wallet should in principle avoid:

* full witness expansion;
* large-scale FFT/NTT;
* large-scale MSM;
* storing the full proving key;
* storing the full extended witness;
* storing multiple linear-size large vectors.

These objectives must be evaluated against concrete circuits, credential formats, proving systems, and mobile devices.

### 6.2 Single-Server Deployment

In this project, "single-server" denotes a single administrative and trust domain rather than a single physical machine. The provider may use multiple machines, CPUs, GPUs, or internal workers, but privacy must not depend on any non-collusion assumption among them.

### 6.3 Credential and Witness Privacy

The untrusted host software and prover accelerator must not learn undisclosed credential contents, hidden attributes, the full witness, or the long-term holder secret. A confidential component may process sensitive values in plaintext only under explicitly stated hardware or cryptographic assumptions. The final security model must distinguish the cloud operator, untrusted host software, confidential execution component, and external accelerator.

### 6.4 Holder Authorization

Each authorization should bind at least the following fields:

* credential reference;
* predicate;
* disclosed attributes;
* verifier identity/domain;
* fresh nonce;
* expiration;
* protocol version;
* circuit or policy identifier.

This binding is intended to prevent a server from reusing a holder's authorization outside the request context that the holder approved.

### 6.5 Malicious-Server Security with Abort

The server may modify requests, replay messages, interleave parallel sessions, return incorrect results, collude with the verifier, or abort. The system does not aim to guarantee availability against a malicious server, but it should protect credential privacy, request integrity, and holder authorization despite these behaviors.

### 6.6 Practical Mobile Deployment

The final system must be evaluated on real Android phones and real cloud servers. The evaluation should measure latency, CPU usage, peak RSS, storage, communication, energy consumption, thermal behavior, and repeated-run stability. The Android Emulator may be useful for development and debugging, but it cannot replace formal performance experiments on physical phones.

## 7. Tentative System Model

The initial system model contains four entities.

### Issuer

The issuer creates and issues a credential, and binds that credential to a holder-controlled key or authorization mechanism.

### Mobile Wallet

The mobile wallet stores a minimal holder-controlled secret, displays presentation requests, obtains user confirmation, generates request-specific authorization, and verifies the server's result.

### Single Cloud Service

The single cloud service is tentatively divided into two components:

1. a private or confidential component;
2. an untrusted high-performance prover accelerator.

The private or confidential component may execute credential recovery, authorization validation, witness generation, secret-dependent computation, and masking.

The untrusted high-performance prover accelerator may execute proving-key storage, MSM, FFT/NTT, polynomial operations, and GPU acceleration.

The final mechanism for realizing this split has not yet been determined. Candidate directions may include TEE, confidential VM, FHE, or a cryptographic split prover, but the project has not yet committed to one of these designs.

### Verifier

The verifier generates a fresh presentation request, verifies the resulting proof, and learns only the information that the holder is allowed to disclose.

## 8. Initial Threat Model

The initial attacker controls the cloud service. The attacker may read ordinary server memory, store historical transcripts, replay authorizations, replace the verifier, predicate, disclosure set, credential, or nonce, interleave parallel sessions, return incorrect computations, selectively abort, and collude with the verifier.

The initial model temporarily trusts:

* the holder authorization key is not leaked;
* the phone correctly displays the canonical request;
* the issuer public key;
* SNARK soundness;
* the underlying signature and encryption primitives;
* if a TEE is used, attestation and isolation.

The threat model explicitly assumes that:

* a malicious server can always deny service;
* fully hiding network metadata is not a current goal;
* a fully compromised mobile operating system is outside the initial model.

## 9. Research Hypotheses to Validate

The project starts from the following hypotheses. Each one must be validated through literature review, implementation experiments, or security analysis before it can be treated as a research claim.

* H1: After MSM outsourcing, witness generation, witness-dependent field computation, communication, or memory may still become the mobile bottleneck.
* H2: Outsourcing only MSM may be insufficient to create a genuinely thin mobile client.
* H3: Moving witness generation and the main proving computation to a single server can significantly reduce the mobile wallet's online cost.
* H4: Without holder-bound authorization, a server that stores long-term credential-related state may gain the ability to generate presentations independently of the holder.
* H5: A combination of holder authorization, private witness processing, and untrusted proving acceleration may form a deployable architecture for mobile credential proving.

## 10. Scope for the Initial Prototype

The initial MVP is frozen to keep the prototype concrete and measurable:

* the client starts as a Rust CLI and later migrates to Android;
* later versions should use Android hardware-backed Keystore;
* the initial proof system is Groth16;
* the prototype implements one credential presentation circuit;
* the predicate is `age >= 18`;
* each request binds the verifier, nonce, predicate, disclosure set, and credential reference;
* the server is a single-server Linux implementation;
* the first version runs a normal cloud prover, then adds a private witness component and split proving;
* the final evaluation uses at least one or two real Android phones.

This scope is intentionally narrow. It should support end-to-end evaluation before generalizing to additional credential formats, circuits, proof systems, or mobile platforms.

## 11. Explicit Non-Goals

The initial project does not attempt to:

* design multi-server MPC proving;
* rely on non-collusion among internal workers operated by the same company;
* support every SNARK backend in the first version;
* implement a general-purpose FHE prover in the first version;
* guarantee that a malicious server completes proof generation;
* fully hide network side channels;
* directly integrate with private Apple Wallet interfaces;
* handle a fully compromised mobile operating system;
* place the entire prover inside a TEE as the final contribution;
* assume in advance that memory is necessarily the only or largest bottleneck.

These non-goals are meant to keep the research question focused on single-server delegated proving for mobile credential wallets rather than on all possible wallet, infrastructure, and platform security problems.

## 12. Expected Research Contributions

The expected contributions are tentative and depend on the outcome of the literature review, prototype, and evaluation:

1. Measurements of single-server outsourcing for realistic credential workloads on real mobile phones.
2. A security abstraction for holder-authorized delegated proving.
3. A private witness generation method or memory-bounded split prover suitable for a thin mobile wallet.
4. A single-server mobile credential proving prototype and evaluation.

## Initial Novelty Boundary

The project is not intended to contribute only another outsourced MSM protocol or a mobile wrapper around an existing cloud prover. Its intended research boundary is the combination of:

1. end-to-end delegation beginning from compact credential state rather than an already-materialized witness;
2. a single administrative trust domain;
3. explicit holder authorization for every presentation context; and
4. a thin mobile client evaluated on real phones.

Whether this combination is novel remains subject to the related-work study.

## Claim Tiers

### Minimum Publishable Claim

A mobile wallet can delegate credential proving to one administrative cloud domain while retaining cryptographic control over the authorized presentation request, with significantly lower mobile resource usage than local proving.

### Stretch Claim

The system additionally avoids materializing the full witness and large prover state inside both the phone and the confidential component through a memory-bounded split prover.

## 13. Open Design Decisions

| Decision | Candidate Options | Evidence Needed |
| --- | --- | --- |
| Private witness execution | TEE / confidential VM / FHE / cryptographic split prover | Security assumptions, implementation effort, leakage surface, performance, and deployability |
| Proof backend | Groth16 / Plonkish / multilinear sumcheck | Circuit fit, prover cost, verifier cost, key size, mobile compatibility, and outsourcing structure |
| Holder authorization | signature binding / decryption share / both | Ability to prevent replay, request substitution, and independent server-side credential use |
| Credential storage | phone / encrypted cloud / split storage | Privacy, recovery, storage pressure, authorization flow, and operational risk |
| Prover partition | manual / compiler-assisted | Engineering complexity, correctness risk, reusable abstractions, and measured mobile savings |
| Mobile verification | local / verifier only / both | User assurance, cost on phone, protocol simplicity, and compatibility with verifier workflows |
| Revocation | Merkle tree / accumulator / SNARK state check | Credential ecosystem requirements, circuit cost, update cost, and privacy impact |

## 14. Success Criteria

The project should be considered successful only if it reaches measurable and security-relevant milestones:

* holder authorization is formalized clearly enough to support security analysis;
* an end-to-end credential presentation prototype is implemented;
* without current phone authorization, the server cannot generate a valid presentation for a different request;
* undisclosed credential contents are not exposed outside the explicitly defined private computation boundary, under the stated cryptographic or confidential-computing assumptions;
* the phone does not execute full proving;
* at least one real Android phone is used in the evaluation;
* the system is compared with local proving, plain cloud proving, and a feasible EMSM baseline;
* latency, memory, communication, energy consumption, and server-side overhead are evaluated;
* replay, request substitution, credential substitution, and malicious abort tests are performed.

These criteria are intended to prevent the work from stopping at a partial optimization or an architecture sketch without end-to-end evidence.

## Current Status

This document defines the initial research scope as of June 29, 2026. All novelty claims, performance assumptions, and architectural choices remain subject to literature review, implementation, and experimental validation.
