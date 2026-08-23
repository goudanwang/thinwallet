#[path = "../credential_workloads.rs"]
mod credential_workloads;
#[path = "../profile_s_issuance.rs"]
mod profile_s_issuance;

use anyhow::{anyhow, Result};
use credential_workloads::profile_s::{
    build_profile_s, minimum_profile_s_log, native_commitment_for_fixture, ProfileSMutation,
    ProfileSWorkload,
};
use ed25519_dalek::{Signer, SigningKey};
use libspartan_patched as patched;
use profile_s_issuance::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::time::Instant;

#[derive(Serialize)]
struct Check {
    expected: &'static str,
    observed: String,
    passed: bool,
}

fn record<T: std::fmt::Debug>(result: Result<T, ProfileSError>, expected_ok: bool) -> Check {
    let passed = result.is_ok() == expected_ok;
    Check {
        expected: if expected_ok { "accept" } else { "reject" },
        observed: match result {
            Ok(_) => "accepted".into(),
            Err(error) => format!("rejected: {error}"),
        },
        passed,
    }
}

fn deterministic_keys(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn fixture_package_index(signing_key: &SigningKey, index: usize) -> CredentialPackage {
    let salt = curve25519_dalek::scalar::Scalar::from(0xa5a5_0000u64 + index as u64).to_bytes();
    issue_package(
        signing_key,
        0x5457_5343,
        700 + index as u64,
        native_commitment_for_fixture(index),
        41,
        PrivateCredentialFields {
            credential_id: 0x5000 + index as u64,
            holder_secret: 0x5151,
            age: 24,
            country: 36,
            expiry: 25_000,
            revocation_id: 5 + index as u64,
            schema_id: 90 + index as u64,
        },
        salt,
    )
}

fn fixture_package(signing_key: &SigningKey) -> CredentialPackage {
    fixture_package_index(signing_key, 0)
}

fn run_issuance_audit() -> serde_json::Value {
    let issuer = deterministic_keys(7);
    let mut registry = IssuerRegistry::default();
    let key_id = registry
        .register(700, issuer.verifying_key().to_bytes())
        .expect("valid key");
    let package = fixture_package(&issuer);
    assert_eq!(key_id, package.issuer_public_key_id);
    let mut tests = BTreeMap::new();
    tests.insert(
        "valid_issuance",
        record(registry.verify_package(&package), true),
    );
    let issuer_two = deterministic_keys(8);
    registry
        .register(701, issuer_two.verifying_key().to_bytes())
        .expect("valid second key");
    let package_two = fixture_package_index(&issuer_two, 1);
    tests.insert(
        "valid_second_issuer",
        record(registry.verify_package(&package_two), true),
    );

    let mut changed = package.clone();
    changed.credential_commitment[0] ^= 1;
    tests.insert(
        "modified_commitment",
        record(registry.verify_package(&changed), false),
    );
    let mut changed = package.clone();
    changed.issuer_id += 1;
    tests.insert(
        "modified_issuer_id",
        record(registry.verify_package(&changed), false),
    );
    let mut changed = package.clone();
    changed.credential_type += 1;
    tests.insert(
        "modified_credential_type",
        record(registry.verify_package(&changed), false),
    );
    let mut changed = package.clone();
    changed.issuance_epoch += 1;
    tests.insert(
        "modified_epoch",
        record(registry.verify_package(&changed), false),
    );
    let mut changed = package.clone();
    changed.signature[0] ^= 1;
    tests.insert(
        "invalid_signature",
        record(registry.verify_package(&changed), false),
    );
    let mut malformed = package.clone();
    malformed.signature = [0xff; 64];
    tests.insert(
        "malformed_signature",
        record(registry.verify_package(&malformed), false),
    );

    let mut bad_registry = IssuerRegistry::default();
    let malformed_key = bad_registry.register(700, [0u8; 32]);
    tests.insert("malformed_public_key", record(malformed_key, false));

    let encoded = encode_package(&package);
    let canonical_roundtrip = decode_package(&encoded).map(|decoded| decoded == package);
    tests.insert(
        "canonical_roundtrip",
        Check {
            expected: "accept",
            observed: format!("{canonical_roundtrip:?}"),
            passed: matches!(canonical_roundtrip, Ok(true)),
        },
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    tests.insert(
        "noncanonical_trailing_bytes",
        record(decode_package(&trailing), false),
    );
    let mut noncanonical_scalar = encoded;
    let commitment_offset = 8 + 2 + 8 + 8 + 32;
    noncanonical_scalar[commitment_offset..commitment_offset + 32].fill(0xff);
    tests.insert(
        "noncanonical_field_encoding",
        record(decode_package(&noncanonical_scalar), false),
    );
    let all_passed = tests.values().all(|test| test.passed);
    serde_json::json!({
        "backend": "ed25519-dalek",
        "version": "2.2.0",
        "specification": "RFC 8032 Ed25519",
        "verification": "VerifyingKey::verify_strict; individual verification only",
        "public_key_bytes": 32,
        "signature_bytes": 64,
        "canonical_package_bytes": PACKAGE_SIZE,
        "tests": tests,
        "all_passed": all_passed,
        "classification": if all_passed { "PROFILE_S_ISSUANCE_PASS" } else { "PUBLIC_KEY_SIGNATURE_BACKEND_BLOCKED" },
    })
}

const PACKAGE_SIZE: usize = 8 + 2 + 8 + 8 + 32 + 32 + 8 + 64 + 7 * 8 + 32;

fn run_revocation_audit() -> serde_json::Value {
    let registry_key = deterministic_keys(11);
    let root = curve25519_dalek::scalar::Scalar::from(0x1234u64).to_bytes();
    let statement = RevocationStatement {
        protocol_version: PROTOCOL_VERSION,
        registry_id: 900,
        credential_type: 0x5457_5343,
        sparse_merkle_root: root,
        epoch: 73,
        valid_from: 10_000,
        valid_until: 20_000,
    };
    let signed = sign_revocation(&registry_key, statement);
    let verify = |value: &SignedRevocationStatement,
                  key: &SigningKey,
                  registry,
                  ty,
                  minimum_epoch,
                  maximum_epoch,
                  now| {
        verify_revocation(
            &key.verifying_key(),
            value,
            registry,
            ty,
            minimum_epoch,
            maximum_epoch,
            now,
        )
    };
    let mut tests = BTreeMap::new();
    tests.insert(
        "valid_current_root",
        record(
            verify(&signed, &registry_key, 900, 0x5457_5343, 73, 73, 15_000),
            true,
        ),
    );
    let mut changed = signed.clone();
    changed.statement.sparse_merkle_root[0] ^= 1;
    tests.insert(
        "modified_root",
        record(
            verify(&changed, &registry_key, 900, 0x5457_5343, 73, 73, 15_000),
            false,
        ),
    );
    tests.insert(
        "wrong_registry_key",
        record(
            verify(
                &signed,
                &deterministic_keys(12),
                900,
                0x5457_5343,
                73,
                73,
                15_000,
            ),
            false,
        ),
    );
    tests.insert(
        "stale_epoch",
        record(
            verify(&signed, &registry_key, 900, 0x5457_5343, 74, 74, 15_000),
            false,
        ),
    );
    let mut future_statement = signed.statement.clone();
    future_statement.epoch = 74;
    let signed_future = sign_revocation(&registry_key, future_statement);
    tests.insert(
        "future_epoch",
        record(
            verify(
                &signed_future,
                &registry_key,
                900,
                0x5457_5343,
                73,
                73,
                15_000,
            ),
            false,
        ),
    );
    tests.insert(
        "not_yet_valid",
        record(
            verify(&signed, &registry_key, 900, 0x5457_5343, 73, 73, 9_999),
            false,
        ),
    );
    tests.insert(
        "expired_window",
        record(
            verify(&signed, &registry_key, 900, 0x5457_5343, 73, 73, 20_001),
            false,
        ),
    );
    tests.insert(
        "cross_type_replay",
        record(
            verify(&signed, &registry_key, 900, 0x5457_5344, 73, 73, 15_000),
            false,
        ),
    );
    let all_passed = tests.values().all(|test| test.passed);
    serde_json::json!({
        "statement": signed.statement,
        "tests": tests,
        "all_passed": all_passed,
        "classification": if all_passed { "SIGNED_REVOCATION_STATE_PASS" } else { "PHASE_V4C_BLOCKED_REVOCATION_AUTHENTICATION" },
    })
}

fn relation_sat(workload: ProfileSWorkload, mutation: ProfileSMutation) -> Result<bool> {
    let log = minimum_profile_s_log(workload);
    let n = 1usize << log;
    let fixture = build_profile_s(workload, mutation, n).map_err(|error| anyhow!(error))?;
    let instance = patched::Instance::new(
        n,
        n,
        fixture.inputs.len(),
        &fixture.a,
        &fixture.b,
        &fixture.c,
    )
    .map_err(|error| anyhow!("{error:?}"))?;
    let vars = patched::VarsAssignment::new(&fixture.vars).map_err(|error| anyhow!("{error:?}"))?;
    let inputs =
        patched::InputsAssignment::new(&fixture.inputs).map_err(|error| anyhow!("{error:?}"))?;
    instance
        .is_sat(&vars, &inputs)
        .map_err(|error| anyhow!("{error:?}"))
}

fn run_relation_audit() -> Result<serde_json::Value> {
    let mut workloads = BTreeMap::new();
    for workload in [
        ProfileSWorkload::W1,
        ProfileSWorkload::W2,
        ProfileSWorkload::W3,
        ProfileSWorkload::W4,
    ] {
        let log = minimum_profile_s_log(workload);
        let mut construction_samples = Vec::new();
        let mut witness_samples = Vec::new();
        let mut fixture = None;
        for _ in 0..5 {
            let sample = build_profile_s(workload, ProfileSMutation::Valid, 1usize << log)
                .map_err(|error| anyhow!(error))?;
            construction_samples.push(sample.metadata.construction_ms);
            witness_samples.push(sample.metadata.witness_generation_ms);
            fixture = Some(sample);
        }
        let fixture = fixture.expect("five relation samples");
        let mut tests = BTreeMap::new();
        for (name, mutation) in [
            ("valid", ProfileSMutation::Valid),
            ("commitment_opening_mismatch", ProfileSMutation::Commitment),
            ("issuer_substitution", ProfileSMutation::Issuer),
            (
                "credential_type_confusion",
                ProfileSMutation::CredentialType,
            ),
            (
                "issuance_epoch_substitution",
                ProfileSMutation::IssuanceEpoch,
            ),
            ("modified_attribute", ProfileSMutation::Attribute),
            ("wrong_holder", ProfileSMutation::Holder),
            ("wrong_nonce", ProfileSMutation::Nonce),
        ] {
            let sat = relation_sat(workload, mutation)?;
            tests.insert(name, serde_json::json!({"satisfiable": sat, "expected": mutation == ProfileSMutation::Valid, "passed": sat == (mutation == ProfileSMutation::Valid)}));
        }
        if matches!(
            workload,
            ProfileSWorkload::W2 | ProfileSWorkload::W3 | ProfileSWorkload::W4
        ) {
            let sat = relation_sat(workload, ProfileSMutation::Expired)?;
            tests.insert(
                "expired_credential",
                serde_json::json!({"satisfiable":sat,"expected":false,"passed":!sat}),
            );
        }
        if matches!(workload, ProfileSWorkload::W3 | ProfileSWorkload::W4) {
            for (name, mutation) in [
                ("revoked", ProfileSMutation::Revoked),
                ("stale_root", ProfileSMutation::StaleRoot),
                ("malformed_merkle_path", ProfileSMutation::MerklePath),
            ] {
                let sat = relation_sat(workload, mutation)?;
                tests.insert(
                    name,
                    serde_json::json!({"satisfiable":sat,"expected":false,"passed":!sat}),
                );
            }
        }
        if workload == ProfileSWorkload::W4 {
            let sat = relation_sat(workload, ProfileSMutation::CrossCredential)?;
            tests.insert(
                "cross_credential_mismatch",
                serde_json::json!({"satisfiable":sat,"expected":false,"passed":!sat}),
            );
        }
        let passed = tests.values().all(|test| test["passed"] == true);
        workloads.insert(
            workload.name(),
            serde_json::json!({
                "metadata":fixture.metadata,
                "relation_construction":stats(&construction_samples),
                "witness_generation":stats(&witness_samples),
                "tests":tests,
                "all_passed":passed
            }),
        );
    }
    let all_passed = workloads.values().all(|value| value["all_passed"] == true);
    Ok(serde_json::json!({
        "workloads": workloads,
        "all_passed": all_passed,
        "classification": if all_passed { "PROFILE_S_COMMITMENT_OPENING_GADGET_PASS" } else { "PHASE_V4C_BLOCKED_COMMITMENT_BINDING" },
    }))
}

fn run_scaling_shapes() -> Result<serde_json::Value> {
    let configurations = [(1usize, 8usize), (4, 12), (10, 16), (25, 24), (52, 32)];
    let mut rows = Vec::new();
    let mut expected_log = 14usize;
    let mut all_boundaries = true;
    for (credentials, revocation_depth) in configurations {
        let workload = ProfileSWorkload::WK {
            credentials,
            revocation_count: 1,
            revocation_depth,
            revocation_backend: credential_workloads::profile_s::RevocationBackend::SparseMerkle,
        };
        let log = minimum_profile_s_log(workload);
        let fixture = build_profile_s(workload, ProfileSMutation::Valid, 1usize << log)
            .map_err(|error| anyhow!(error))?;
        let useful_only = fixture
            .metadata
            .constraint_composition
            .keys()
            .all(|name| !name.contains("dummy"));
        let boundary_matches = log == expected_log;
        all_boundaries &= boundary_matches && useful_only;
        rows.push(serde_json::json!({
            "configuration":workload.name(),
            "credentials":credentials,
            "revocation_depth":revocation_depth,
            "raw_constraints":fixture.metadata.raw_constraints,
            "raw_variables":fixture.metadata.raw_variables,
            "public_inputs":fixture.metadata.public_inputs,
            "witness_elements":fixture.metadata.witness_elements,
            "padded_log":log,
            "padded_constraints":fixture.metadata.padded_size,
            "padding_ratio":fixture.metadata.padding_constraints as f64 / fixture.metadata.padded_size as f64,
            "q":fixture.metadata.q,
            "m":fixture.metadata.m,
            "fragmented_outputs":fixture.metadata.fragmented_outputs,
            "useful_constraints_only":useful_only,
            "expected_boundary":expected_log,
            "boundary_matches":boundary_matches,
            "constraint_composition":fixture.metadata.constraint_composition,
        }));
        expected_log += 1;
    }
    Ok(serde_json::json!({
        "configurations":rows,
        "all_boundaries":all_boundaries,
        "classification":if all_boundaries { "CREDENTIAL_CROSS_PADDING_SCALING_PASS" } else { "PHASE_V4C_CROSS_PADDING_EVALUATION_INCOMPLETE" },
    }))
}

fn binding_matches_r1cs_inputs(
    statement: &VerifiedCredentialStatement,
    inputs: &[[u8; 32]],
) -> Result<(), ProfileSError> {
    if inputs.len() < 5 || statement.protocol_version != PROTOCOL_VERSION {
        return Err(ProfileSError::InvalidSignature);
    }
    let scalar = |bytes: [u8; 32]| {
        Option::<curve25519_dalek::scalar::Scalar>::from(
            curve25519_dalek::scalar::Scalar::from_canonical_bytes(bytes),
        )
        .ok_or(ProfileSError::NonCanonicalPackage)
    };
    let expected_key_digest =
        curve25519_dalek::scalar::Scalar::from_bytes_mod_order(statement.issuer_public_key_id);
    let matches = scalar(inputs[0])?
        == curve25519_dalek::scalar::Scalar::from(statement.credential_type)
        && scalar(inputs[1])? == curve25519_dalek::scalar::Scalar::from(statement.issuer_id)
        && scalar(inputs[2])? == expected_key_digest
        && scalar(inputs[3])? == curve25519_dalek::scalar::Scalar::from(statement.issuance_epoch)
        && inputs[4] == statement.credential_commitment;
    if matches {
        Ok(())
    } else {
        Err(ProfileSError::InvalidSignature)
    }
}

fn run_external_binding_audit() -> serde_json::Value {
    let issuer_a = deterministic_keys(7);
    let issuer_b = deterministic_keys(8);
    let mut registry = IssuerRegistry::default();
    registry
        .register(700, issuer_a.verifying_key().to_bytes())
        .expect("key A");
    registry
        .register(701, issuer_b.verifying_key().to_bytes())
        .expect("key B");
    let package = fixture_package(&issuer_a);
    let verified = registry.verify_package(&package).expect("valid fixture");
    let second = fixture_package_index(&issuer_b, 1);
    let verified_second = registry
        .verify_package(&second)
        .expect("valid second fixture");
    let fixture = build_profile_s(ProfileSWorkload::W4, ProfileSMutation::Valid, 1usize << 14)
        .expect("S-W4 fixture");
    let mut tests = BTreeMap::new();
    tests.insert(
        "exact_verified_transcript",
        record(
            binding_matches_r1cs_inputs(&verified, &fixture.inputs),
            true,
        ),
    );
    tests.insert(
        "second_issuer_exact_transcript",
        record(
            binding_matches_r1cs_inputs(&verified_second, &fixture.inputs[5..]),
            true,
        ),
    );
    let mut changed_inputs = fixture.inputs.clone();
    changed_inputs[4][0] ^= 1;
    tests.insert(
        "verify_commitment_a_prove_b",
        record(
            binding_matches_r1cs_inputs(&verified, &changed_inputs),
            false,
        ),
    );
    let mut changed_inputs = fixture.inputs.clone();
    changed_inputs[1] = curve25519_dalek::scalar::Scalar::from(701u64).to_bytes();
    tests.insert(
        "verify_issuer_a_prove_b",
        record(
            binding_matches_r1cs_inputs(&verified, &changed_inputs),
            false,
        ),
    );
    let mut changed_inputs = fixture.inputs.clone();
    changed_inputs[0] = curve25519_dalek::scalar::Scalar::from(0x5457_5344u64).to_bytes();
    tests.insert(
        "verify_type_a_prove_b",
        record(
            binding_matches_r1cs_inputs(&verified, &changed_inputs),
            false,
        ),
    );
    let mut changed = verified.clone();
    changed.protocol_version += 1;
    tests.insert(
        "cross_protocol_replay",
        record(
            binding_matches_r1cs_inputs(&changed, &fixture.inputs),
            false,
        ),
    );
    let mut changed_inputs = fixture.inputs.clone();
    changed_inputs[3] = curve25519_dalek::scalar::Scalar::from(42u64).to_bytes();
    tests.insert(
        "replace_public_input_after_verification",
        record(
            binding_matches_r1cs_inputs(&verified, &changed_inputs),
            false,
        ),
    );
    let all_passed = tests.values().all(|test| test.passed);
    serde_json::json!({
        "mechanism": "typed VerifiedCredentialStatement compared field-for-field against the actual R1CS public-input vector before proving; no caller-supplied boolean",
        "tests": tests,
        "all_passed": all_passed,
        "classification": if all_passed { "PROFILE_S_EXTERNAL_SIGNATURE_BINDING_PASS" } else { "PHASE_V4C_BLOCKED_EXTERNAL_SIGNATURE_BINDING" },
    })
}

fn stats(values: &[f64]) -> serde_json::Value {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / (values.len() - 1) as f64;
    serde_json::json!({"raw_ms":values,"mean_ms":mean,"median_ms":sorted[sorted.len()/2],"sd_ms":variance.sqrt(),"min_ms":sorted[0],"max_ms":sorted[sorted.len()-1]})
}

fn signature_benchmark() -> serde_json::Value {
    let key = deterministic_keys(7);
    let message = credential_signature_message(
        PROTOCOL_VERSION,
        0x5457_5343,
        &native_commitment_for_fixture(0),
        41,
    );
    for _ in 0..20 {
        let signature = key.sign(&message);
        key.verifying_key()
            .verify_strict(&message, &signature)
            .expect("warm-up");
    }
    let mut signing = Vec::new();
    let mut verifying = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let signature = key.sign(&message);
        signing.push(start.elapsed().as_secs_f64() * 1000.0);
        let start = Instant::now();
        key.verifying_key()
            .verify_strict(&message, &signature)
            .expect("valid signature");
        verifying.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let signature = key.sign(&message);
    let mut modified_message = message.clone();
    modified_message[0] ^= 1;
    let modified_message_rejected = key
        .verifying_key()
        .verify_strict(&modified_message, &signature)
        .is_err();
    let mut signature_bytes = signature.to_bytes();
    signature_bytes[0] ^= 1;
    let modified_signature_rejected = ed25519_dalek::Signature::from_slice(&signature_bytes)
        .map(|value| key.verifying_key().verify_strict(&message, &value).is_err())
        .unwrap_or(true);
    serde_json::json!({
        "warm_up_operations":20,
        "signing":stats(&signing),
        "strict_verification":stats(&verifying),
        "modified_message_rejected":modified_message_rejected,
        "modified_signature_rejected":modified_signature_rejected,
    })
}

fn main() -> Result<()> {
    let first = std::env::args().nth(1);
    if first.as_deref() == Some("verify-fixture") {
        let issuance = run_issuance_audit();
        let revocation = run_revocation_audit();
        let binding = run_external_binding_audit();
        let passed = issuance["all_passed"] == true
            && revocation["all_passed"] == true
            && binding["all_passed"] == true;
        println!(
            "{}",
            serde_json::to_string(
                &serde_json::json!({"passed":passed,"issuance":issuance["classification"],"revocation":revocation["classification"],"binding":binding["classification"]})
            )?
        );
        return if passed {
            Ok(())
        } else {
            Err(anyhow!("external Profile S verification failed"))
        };
    }
    let output = first
        .unwrap_or_else(|| "../credential_workloads/results/phase_v4c_profile_s_audit.json".into());
    let issuance = run_issuance_audit();
    let revocation = run_revocation_audit();
    let relation = run_relation_audit()?;
    let external_binding = run_external_binding_audit();
    let scaling = run_scaling_shapes()?;
    let benchmark = signature_benchmark();
    let all_passed = issuance["all_passed"] == true
        && revocation["all_passed"] == true
        && relation["all_passed"] == true
        && external_binding["all_passed"] == true
        && scaling["all_boundaries"] == true;
    let report = serde_json::json!({
        "signature_backend": {"name":"Ed25519","crate":"ed25519-dalek","version":"2.2.0","specification":"RFC 8032","batch_policy":"disabled; strict individual verification"},
        "issuance":issuance,
        "signed_revocation":revocation,
        "r1cs":relation,
        "external_signature_binding":external_binding,
        "cross_padding_shapes":scaling,
        "external_signature_benchmark":benchmark,
        "all_passed":all_passed,
    });
    if let Some(parent) = std::path::Path::new(&output).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    let digest = Sha256::digest(fs::read(&output)?);
    println!(
        "{} {}",
        output,
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    if all_passed {
        Ok(())
    } else {
        Err(anyhow!("Profile S audit failed"))
    }
}
