use anyhow::{anyhow, Result};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[path = "../credential_source/mod.rs"]
mod credential_source;
#[path = "../credential_workloads.rs"]
mod credential_workloads;

use credential_source::{
    credential_package_digest, digest_bytes, CredentialRelationReplay, CredentialSourceHeader,
    CredentialSourceJournal, CredentialSourceReader, CredentialSourceRecord,
    CredentialSourceWriter, CredentialWitnessReplay, ExpectedCredentialSourceBinding,
    SoftwareCredentialSourceKeyProvider,
};
use credential_workloads::profile_s::{
    build_profile_s, build_profile_s_from_records, minimum_profile_s_log, ProfileSMutation,
    ProfileSReplayRecord, ProfileSWorkload, RevocationBackend,
};
use credential_workloads::RelationFixture;

#[derive(Serialize)]
struct WorkloadResult {
    workload: String,
    alias: Option<&'static str>,
    authenticated_source_path: String,
    authenticated_source_sha256: String,
    authenticated_source_digest: String,
    proof_session_id: String,
    relation_layout_digest: String,
    public_input_digest: String,
    witness_digest: String,
    raw_constraints: usize,
    padded_constraints: usize,
    public_inputs: usize,
    witness_elements: usize,
    sparse_nonzero_entries: usize,
    max_sparse_matrix_entries: usize,
    q: usize,
    m: usize,
    fragmented_outputs: usize,
    revocation_count: usize,
    revocation_depth: usize,
    revocation_backend: String,
    path_sibling_count: usize,
    raw_constraint_delta_from_r0: Option<usize>,
    relation_construction_ms: f64,
    witness_generation_ms: f64,
    authenticated_source_bytes: u64,
    pbmo_token_size_bytes: Option<usize>,
    proof_size_bytes: Option<usize>,
    upload_bytes: Option<usize>,
    download_bytes: Option<usize>,
    peak_rss_mb: Option<f64>,
    temporary_storage_bytes: Option<u64>,
    wall_latency_ms: Option<f64>,
}

#[derive(Serialize)]
struct AuditResult {
    classification: &'static str,
    semantics: &'static str,
    historical_alias: &'static str,
    source_authentication: &'static str,
    bounded_record_replay: bool,
    relation_byte_identical: bool,
    witness_byte_identical: bool,
    transcript_byte_identical: Option<bool>,
    proof_byte_identical: Option<bool>,
    unchanged_native_verifier: Option<bool>,
    full_prover_identity: Option<FullProverIdentity>,
    relation_digest: String,
    relation_replay_digest: String,
    witness_replay_digest: String,
    authenticated_replay_session_id: String,
    security_tests: Vec<SecurityResult>,
    composition_scaling: Vec<WorkloadResult>,
    revocation_scaling: Vec<WorkloadResult>,
    revocation_policy_profiles: Vec<WorkloadResult>,
    notes: Vec<&'static str>,
}

#[derive(Serialize)]
struct FullProverIdentity {
    workload: &'static str,
    proof_sha256: String,
    proof_size_bytes: u64,
    transcript_sha256: String,
    transcript_size_bytes: u64,
    transcript_event_count: usize,
    in_memory_prove_ms: f64,
    authenticated_replay_prove_ms: f64,
    in_memory_peak_rss_mb: f64,
    authenticated_replay_peak_rss_mb: f64,
    patched_verifier_accepts: bool,
    unchanged_upstream_verifier_accepts: bool,
}

#[derive(Serialize)]
struct SecurityResult {
    name: &'static str,
    passed: bool,
}

fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let results = root.join("../credential_workloads/results/v4e");
    let sources = results.join("sources");
    fs::create_dir_all(&sources)?;
    let provider =
        SoftwareCredentialSourceKeyProvider::new("thinwallet-v4e-software-key-1", [0x5au8; 32]);

    let canonical = wk(8, 2, 32, RevocationBackend::SparseMerkle);
    let padded = 1usize << minimum_profile_s_log(canonical);
    let fixture = build_profile_s(canonical, ProfileSMutation::Valid, padded)
        .map_err(|error| anyhow!(error))?;
    let (header, records) = source_fixture(canonical, &fixture, 7)?;
    let source_path = sources.join("WK_k8_r2_d32_sparse_merkle.twcs");
    let mut rng = StdRng::seed_from_u64(0x5634_4501);
    let written = CredentialSourceWriter::write(
        &source_path,
        provider.key_id(),
        &provider,
        header,
        &records,
        &mut rng,
    )?;
    let expected = ExpectedCredentialSourceBinding::from_header(&written);
    let reader = CredentialSourceReader::open(&source_path, &provider, &expected)?;
    let replay_fixture = replay_relation(&reader, canonical, padded)?;
    let relation_byte_identical = fixture_equal(&fixture, &replay_fixture);
    let witness_byte_identical = fixture.vars == replay_fixture.vars;

    let relation_replay_digest = CredentialRelationReplay(&reader).replay_digest()?;
    let witness_replay_digest = CredentialWitnessReplay(&reader).replay_digest()?;
    let security_tests = run_security_tests(&results, &source_path, &provider, &written, &records)?;

    let mut composition_scaling = Vec::new();
    for k in [1usize, 4, 10, 25, 52] {
        composition_scaling.push(measure_workload(
            &sources,
            &provider,
            wk(k, 1, 32, RevocationBackend::SparseMerkle),
            None,
        )?);
    }
    let baseline = build_minimal(wk(8, 0, 0, RevocationBackend::None))?
        .metadata
        .raw_constraints;
    let mut revocation_scaling = Vec::new();
    for r in [0usize, 1, 2, 4, 8] {
        let workload = if r == 0 {
            wk(8, 0, 0, RevocationBackend::None)
        } else {
            wk(8, r, 32, RevocationBackend::SparseMerkle)
        };
        revocation_scaling.push(measure_workload(
            &sources,
            &provider,
            workload,
            Some(baseline),
        )?);
    }
    let revocation_policy_profiles = vec![
        measure_workload(
            &sources,
            &provider,
            wk(8, 0, 0, RevocationBackend::None),
            None,
        )?,
        measure_workload(
            &sources,
            &provider,
            wk(8, 0, 0, RevocationBackend::ExpiryOnly),
            None,
        )?,
        measure_workload(
            &sources,
            &provider,
            wk(8, 1, 32, RevocationBackend::SparseMerkle),
            None,
        )?,
    ];

    let all_security = security_tests.iter().all(|test| test.passed);
    let full_prover_identity = load_full_prover_identity(&results.join("identity"))?;
    let classification = if !relation_byte_identical || !witness_byte_identical {
        "PHASE_V4E_BLOCKED_RELATION_MISMATCH"
    } else if !all_security {
        "PHASE_V4E_SECURITY_REGRESSION_INCOMPLETE"
    } else {
        // Full cap-boundary and five-repetition proof evaluation is deliberately
        // not inferred from the source/relation audit.
        "PHASE_V4E_EVALUATION_INCOMPLETE"
    };
    let audit = AuditResult {
        classification,
        semantics: "WK(k,r,d,RevBackend)",
        historical_alias: "WK_52_32_LEGACY -> WK(52,1,32,SparseMerkle)",
        source_authentication: "XChaCha20-Poly1305, separately authenticated header and record frames",
        bounded_record_replay: true,
        relation_byte_identical,
        witness_byte_identical,
        transcript_byte_identical: full_prover_identity.as_ref().map(|_| true),
        proof_byte_identical: full_prover_identity.as_ref().map(|_| true),
        unchanged_native_verifier: full_prover_identity.as_ref().map(|identity| {
            identity.unchanged_upstream_verifier_accepts
        }),
        full_prover_identity,
        relation_digest: hex(&fixture_digest(&fixture)),
        relation_replay_digest: hex(&relation_replay_digest),
        witness_replay_digest: hex(&witness_replay_digest),
        authenticated_replay_session_id: hex(&written.proof_session_id),
        security_tests,
        composition_scaling,
        revocation_scaling,
        revocation_policy_profiles,
        notes: vec![
            "The compact source is an experimental software-key construction, not a production keystore integration.",
            "Native full-prover transcript/proof identity is measured; the complete corrected-workload FS6/FS7 mode/cap matrix remains null.",
            "SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED: the journal detects rollback only relative to retained journal history.",
            "No Android execution occurred.",
        ],
    };
    fs::write(
        results.join("phase_v4e_semantic_audit.json"),
        serde_json::to_vec_pretty(&audit)?,
    )?;
    println!("{classification}");
    Ok(())
}

fn load_full_prover_identity(directory: &Path) -> Result<Option<FullProverIdentity>> {
    let in_memory_proof = directory.join("in_memory.proof.bin");
    let replay_proof = directory.join("authenticated_replay.proof.bin");
    let in_memory_transcript = directory.join("in_memory.transcript.jsonl");
    let replay_transcript = directory.join("authenticated_replay.transcript.jsonl");
    let in_memory_result = directory.join("in_memory.proof.json");
    let replay_result = directory.join("authenticated_replay.proof.json");
    if [
        &in_memory_proof,
        &replay_proof,
        &in_memory_transcript,
        &replay_transcript,
        &in_memory_result,
        &replay_result,
    ]
    .iter()
    .any(|path| !path.exists())
    {
        return Ok(None);
    }
    let in_proof = fs::read(&in_memory_proof)?;
    let replay_proof_bytes = fs::read(&replay_proof)?;
    let in_transcript = fs::read(&in_memory_transcript)?;
    let replay_transcript_bytes = fs::read(&replay_transcript)?;
    if in_proof != replay_proof_bytes || in_transcript != replay_transcript_bytes {
        return Err(anyhow!("full prover identity artifacts differ"));
    }
    let in_result: serde_json::Value = serde_json::from_slice(&fs::read(in_memory_result)?)?;
    let replay_result: serde_json::Value = serde_json::from_slice(&fs::read(replay_result)?)?;
    let number = |value: &serde_json::Value, field: &str| -> Result<f64> {
        value[field]
            .as_f64()
            .ok_or_else(|| anyhow!("missing numeric identity field {field}"))
    };
    let accepted = |value: &serde_json::Value, field: &str| -> Result<bool> {
        value[field]
            .as_bool()
            .ok_or_else(|| anyhow!("missing verifier identity field {field}"))
    };
    Ok(Some(FullProverIdentity {
        workload: "WK(8,2,32,SparseMerkle), native deterministic identity fixture",
        proof_sha256: hex(&Sha256::digest(&in_proof)),
        proof_size_bytes: in_proof.len() as u64,
        transcript_sha256: hex(&Sha256::digest(&in_transcript)),
        transcript_size_bytes: in_transcript.len() as u64,
        transcript_event_count: in_transcript.iter().filter(|byte| **byte == b'\n').count(),
        in_memory_prove_ms: number(&in_result, "prove_ms")?,
        authenticated_replay_prove_ms: number(&replay_result, "prove_ms")?,
        in_memory_peak_rss_mb: number(&in_result, "peak_rss_mb")?,
        authenticated_replay_peak_rss_mb: number(&replay_result, "peak_rss_mb")?,
        patched_verifier_accepts: accepted(&in_result, "patched_verifier_accepts")?
            && accepted(&replay_result, "patched_verifier_accepts")?,
        unchanged_upstream_verifier_accepts: accepted(
            &in_result,
            "original_upstream_verifier_accepts",
        )? && accepted(
            &replay_result,
            "original_upstream_verifier_accepts",
        )?,
    }))
}

fn wk(k: usize, r: usize, d: usize, backend: RevocationBackend) -> ProfileSWorkload {
    ProfileSWorkload::WK {
        credentials: k,
        revocation_count: r,
        revocation_depth: d,
        revocation_backend: backend,
    }
}

fn build_minimal(workload: ProfileSWorkload) -> Result<RelationFixture> {
    let log = minimum_profile_s_log(workload);
    build_profile_s(workload, ProfileSMutation::Valid, 1usize << log)
        .map_err(|error| anyhow!(error))
}

fn source_fixture(
    workload: ProfileSWorkload,
    fixture: &RelationFixture,
    generation: u64,
) -> Result<(CredentialSourceHeader, Vec<CredentialSourceRecord>)> {
    let ProfileSWorkload::WK {
        credentials,
        revocation_count,
        revocation_depth,
        revocation_backend,
    } = workload
    else {
        return Err(anyhow!("source fixture requires WK"));
    };
    let relation_layout_digest = fixture_digest(fixture);
    let public_input_digest = digest_bytes(
        b"thinwallet/public-inputs/v1",
        &fixture
            .inputs
            .iter()
            .map(|value| value.as_slice())
            .collect::<Vec<_>>(),
    );
    let revocation_set: Vec<u32> = (0..revocation_count as u32).collect();
    let (_, registry_root) = if revocation_backend == RevocationBackend::SparseMerkle {
        credential_workloads::profile_s::fixture_revocation_material(
            revocation_count,
            0,
            revocation_depth,
        )
    } else {
        (Vec::new(), [0; 32])
    };
    let mut records = Vec::with_capacity(credentials);
    for index in 0..credentials {
        let selected = index < revocation_count;
        let scalar = |value: u64| curve25519_dalek::scalar::Scalar::from(value).to_bytes();
        let mut record = CredentialSourceRecord {
            credential_index: index as u32,
            credential_package_digest: [0; 32],
            issuer_id: 700 + index as u64,
            issuer_public_key_digest:
                credential_workloads::profile_s::native_issuer_key_digest_for_fixture(index),
            credential_type: 0x5457_5343,
            signed_credential_commitment:
                credential_workloads::profile_s::native_commitment_for_fixture(index).to_vec(),
            issuance_epoch: 41,
            commitment_salt: scalar(0xa5a5_0000 + index as u64),
            hidden_attributes: vec![
                scalar(0x5000 + index as u64),
                scalar(90 + index as u64),
                scalar(24),
                scalar(36),
            ],
            disclosed_attribute_bindings: vec![scalar(0)],
            holder_binding: scalar(0x5151),
            expiry: 25_000,
            revocation_identifier: 5 + index as u64,
            predicate_parameters: vec![scalar(18), scalar(65), scalar(24_000)],
            revocation_policy: selected,
            leaf_value: selected.then_some([0; 32]),
            path_index: selected.then_some(5 + index as u64),
            revocation_witness: if selected {
                credential_workloads::profile_s::fixture_revocation_material(
                    revocation_count,
                    index,
                    revocation_depth,
                )
                .0
            } else {
                Vec::new()
            },
        };
        record.credential_package_digest = credential_package_digest(&record)?;
        records.push(record);
    }
    let header = CredentialSourceHeader {
        source_format_version: 1,
        protocol_version: "thinwallet-v4e-1".into(),
        backend_revision: "libspartan-0.9.0-thinwallet-fs7".into(),
        relation_layout_digest,
        proof_session_id: digest_bytes(
            b"thinwallet/proof-session/v1",
            &[workload.name().as_bytes(), &generation.to_be_bytes()],
        ),
        credential_count: credentials as u32,
        revocation_count: revocation_count as u32,
        revocation_depth: revocation_depth as u32,
        revocation_backend: revocation_backend.label().into(),
        revocation_set,
        registry_id: "thinwallet-v4e-test-registry".into(),
        registry_root,
        registry_epoch: 73,
        public_input_digest,
        source_generation: generation,
        source_length: 0,
        source_digest: [0; 32],
    };
    Ok((header, records))
}

fn replay_relation(
    reader: &CredentialSourceReader,
    workload: ProfileSWorkload,
    padded: usize,
) -> Result<RelationFixture> {
    let mut expected_index = 0u32;
    let mut records = Vec::with_capacity(reader.header().credential_count as usize);
    reader.for_each_record(|record| {
        if record.credential_index != expected_index {
            return Err(credential_source::CredentialSourceError::Format(
                "replay index mismatch".into(),
            ));
        }
        expected_index += 1;
        let value = |bytes: &[u8; 32]| {
            if bytes[8..].iter().any(|byte| *byte != 0) {
                return Err(credential_source::CredentialSourceError::Format(
                    "fixture integer exceeds u64".into(),
                ));
            }
            let mut lower = [0u8; 8];
            lower.copy_from_slice(&bytes[..8]);
            Ok(u64::from_le_bytes(lower))
        };
        if record.hidden_attributes.len() != 4 || record.signed_credential_commitment.len() != 32 {
            return Err(credential_source::CredentialSourceError::Format(
                "Profile S replay field count mismatch".into(),
            ));
        }
        let mut expected_commitment = [0u8; 32];
        expected_commitment.copy_from_slice(&record.signed_credential_commitment);
        records.push(ProfileSReplayRecord {
            credential_type: record.credential_type,
            issuer_id: record.issuer_id,
            credential_id: value(&record.hidden_attributes[0])?,
            holder_secret: value(&record.holder_binding)?,
            schema_id: value(&record.hidden_attributes[1])?,
            age: value(&record.hidden_attributes[2])?,
            country: value(&record.hidden_attributes[3])?,
            expiry: record.expiry,
            revocation_id: record.revocation_identifier,
            issuance_epoch: record.issuance_epoch,
            salt: record.commitment_salt,
            issuer_key_digest: record.issuer_public_key_digest,
            expected_commitment,
            revocation_path: record.revocation_witness.clone(),
        });
        Ok(())
    })?;
    if expected_index != reader.header().credential_count {
        return Err(anyhow!("replay element count mismatch"));
    }
    let fixture =
        build_profile_s_from_records(workload, padded, &records).map_err(|error| anyhow!(error))?;
    if fixture_digest(&fixture) != reader.header().relation_layout_digest {
        return Err(anyhow!("relation layout digest mismatch after replay"));
    }
    Ok(fixture)
}

fn measure_workload(
    sources: &Path,
    provider: &SoftwareCredentialSourceKeyProvider,
    workload: ProfileSWorkload,
    baseline: Option<usize>,
) -> Result<WorkloadResult> {
    let fixture = build_minimal(workload)?;
    let (header, records) = source_fixture(workload, &fixture, 1)?;
    let path = sources.join(format!("{}.twcs", workload.name().replace('-', "_")));
    let mut rng = StdRng::seed_from_u64(0x5634_4500 + fixture.metadata.raw_constraints as u64);
    let written = CredentialSourceWriter::write(
        &path,
        provider.key_id(),
        provider,
        header,
        &records,
        &mut rng,
    )?;
    let source_bytes_raw = fs::read(&path)?;
    let source_bytes = source_bytes_raw.len() as u64;
    let ProfileSWorkload::WK {
        revocation_count,
        revocation_depth,
        revocation_backend,
        ..
    } = workload
    else {
        unreachable!()
    };
    Ok(WorkloadResult {
        workload: workload.paper_name(),
        alias: (workload == wk(52, 1, 32, RevocationBackend::SparseMerkle))
            .then_some("WK_52_32_LEGACY"),
        authenticated_source_path: format!(
            "experiments/credential_workloads/results/v4e/sources/{}",
            path.file_name().unwrap().to_string_lossy()
        ),
        authenticated_source_sha256: hex(&Sha256::digest(&source_bytes_raw)),
        authenticated_source_digest: hex(&written.source_digest),
        proof_session_id: hex(&written.proof_session_id),
        relation_layout_digest: hex(&written.relation_layout_digest),
        public_input_digest: hex(&written.public_input_digest),
        witness_digest: hex(&digest_bytes(
            b"thinwallet/witness/v1",
            &fixture
                .vars
                .iter()
                .map(|value| value.as_slice())
                .collect::<Vec<_>>(),
        )),
        raw_constraints: fixture.metadata.raw_constraints,
        padded_constraints: fixture.metadata.padded_size,
        public_inputs: fixture.metadata.public_inputs,
        witness_elements: fixture.metadata.witness_elements,
        sparse_nonzero_entries: fixture.a.len() + fixture.b.len() + fixture.c.len(),
        max_sparse_matrix_entries: fixture.a.len().max(fixture.b.len()).max(fixture.c.len()),
        q: fixture.metadata.q,
        m: fixture.metadata.m,
        fragmented_outputs: fixture.metadata.fragmented_outputs,
        revocation_count,
        revocation_depth,
        revocation_backend: revocation_backend.label().into(),
        path_sibling_count: revocation_count * revocation_depth,
        raw_constraint_delta_from_r0: baseline.map(|base| fixture.metadata.raw_constraints - base),
        relation_construction_ms: fixture.metadata.construction_ms,
        witness_generation_ms: fixture.metadata.witness_generation_ms,
        authenticated_source_bytes: source_bytes,
        pbmo_token_size_bytes: None,
        proof_size_bytes: None,
        upload_bytes: None,
        download_bytes: None,
        peak_rss_mb: None,
        temporary_storage_bytes: None,
        wall_latency_ms: None,
    })
}

fn run_security_tests(
    results: &Path,
    source: &Path,
    provider: &SoftwareCredentialSourceKeyProvider,
    header: &CredentialSourceHeader,
    records: &[CredentialSourceRecord],
) -> Result<Vec<SecurityResult>> {
    let expected = ExpectedCredentialSourceBinding::from_header(header);
    let bytes = fs::read(source)?;
    let rejects_bytes = |name: &'static str, bytes: Vec<u8>| -> Result<SecurityResult> {
        let path = results.join(format!("negative_{name}.twcs"));
        fs::write(&path, bytes)?;
        let passed = CredentialSourceReader::open(&path, provider, &expected).is_err();
        let _ = fs::remove_file(path);
        Ok(SecurityResult { name, passed })
    };
    let mut tests = Vec::new();
    let mut modified = bytes.clone();
    let midpoint = modified.len() / 2;
    modified[midpoint] ^= 1;
    tests.push(rejects_bytes(
        "authenticated_source_byte_modification",
        modified,
    )?);
    let mut tag = bytes.clone();
    let last = tag.len() - 1;
    tag[last] ^= 0x80;
    tests.push(rejects_bytes("source_authentication_tag_corruption", tag)?);
    tests.push(rejects_bytes(
        "source_truncation",
        bytes[..bytes.len() - 9].to_vec(),
    )?);
    let mut extra = bytes.clone();
    extra.extend_from_slice(&[0, 0, 0, 0]);
    tests.push(rejects_bytes("extra_credential_record", extra)?);

    macro_rules! mismatch {
        ($name:literal, $field:ident, $value:expr) => {{
            let mut wrong = expected.clone();
            wrong.$field = $value;
            tests.push(SecurityResult {
                name: $name,
                passed: CredentialSourceReader::open(source, provider, &wrong).is_err(),
            });
        }};
    }
    mismatch!("source_from_another_session", proof_session_id, [9; 32]);
    mismatch!(
        "source_from_another_relation_layout",
        relation_layout_digest,
        [8; 32]
    );
    mismatch!("source_with_another_revset", revocation_set, vec![1, 2]);
    mismatch!(
        "source_with_wrong_revocation_backend",
        revocation_backend,
        "None".into()
    );
    mismatch!("source_with_wrong_registry_root", registry_root, [7; 32]);
    mismatch!("source_with_wrong_registry_epoch", registry_epoch, 74);
    mismatch!(
        "wrong_replay_version",
        protocol_version,
        "thinwallet-v4e-0".into()
    );
    mismatch!("changed_public_inputs", public_input_digest, [6; 32]);
    mismatch!("another_backend_revision", backend_revision, "wrong".into());

    let writer_rejects = |name: &'static str,
                          changed_header: CredentialSourceHeader,
                          changed_records: Vec<CredentialSourceRecord>|
     -> Result<SecurityResult> {
        let path = results.join(format!("writer_reject_{name}.twcs"));
        let mut rng = StdRng::seed_from_u64(77);
        let passed = CredentialSourceWriter::write(
            &path,
            provider.key_id(),
            provider,
            changed_header,
            &changed_records,
            &mut rng,
        )
        .is_err();
        let _ = fs::remove_file(path);
        Ok(SecurityResult { name, passed })
    };
    let source_header = header.clone();
    let mut missing = records.to_vec();
    missing.pop();
    tests.push(writer_rejects(
        "missing_credential_record",
        source_header.clone(),
        missing,
    )?);
    let mut duplicate = records.to_vec();
    duplicate[1].credential_index = 0;
    duplicate[1].credential_package_digest = credential_package_digest(&duplicate[1])?;
    tests.push(writer_rejects(
        "duplicate_credential_index",
        source_header.clone(),
        duplicate,
    )?);
    let mut swapped = records.to_vec();
    swapped.swap(0, 1);
    tests.push(writer_rejects(
        "credential_record_index_swap",
        source_header.clone(),
        swapped,
    )?);
    let mut revset = source_header.clone();
    revset.revocation_set = vec![1, 0];
    tests.push(writer_rejects(
        "noncanonical_revset_order",
        revset,
        records.to_vec(),
    )?);

    for (name, mut changed) in [
        (
            "revocation_path_assigned_to_another_credential",
            records.to_vec(),
        ),
        ("path_index_substitution", records.to_vec()),
        ("revocation_id_substitution", records.to_vec()),
        ("leaf_substitution", records.to_vec()),
        ("sibling_order_swap", records.to_vec()),
        ("truncated_path", records.to_vec()),
        ("extra_path_level", records.to_vec()),
        ("cross_holder_binding_substitution", records.to_vec()),
        ("equality_class_substitution", records.to_vec()),
    ] {
        match name {
            "revocation_path_assigned_to_another_credential" => {
                changed[0].revocation_witness = changed[1].revocation_witness.clone();
                changed[0].revocation_witness[0][0] ^= 1;
            }
            "path_index_substitution" => changed[0].path_index = Some(9),
            "revocation_id_substitution" => changed[0].revocation_identifier += 1,
            "leaf_substitution" => changed[0].leaf_value = Some([1; 32]),
            "sibling_order_swap" => changed[0].revocation_witness.swap(0, 1),
            "truncated_path" => {
                changed[0].revocation_witness.pop();
            }
            "extra_path_level" => changed[0].revocation_witness.push([0; 32]),
            "cross_holder_binding_substitution" => changed[1].holder_binding[0] ^= 1,
            "equality_class_substitution" => changed[1].hidden_attributes[0][0] ^= 1,
            _ => unreachable!(),
        }
        // Deliberately retain the old authenticated package digest.
        tests.push(writer_rejects(name, source_header.clone(), changed)?);
    }

    let mut journal = CredentialSourceJournal::default();
    journal.accept(header)?;
    let mut older = header.clone();
    older.source_generation -= 1;
    tests.push(SecurityResult {
        name: "compact_source_rollback_within_current_journal_history",
        passed: journal.accept(&older).is_err(),
    });
    let reader = CredentialSourceReader::open(source, provider, &expected)?;
    let mut seen = 0usize;
    let injected_abort = reader.for_each_record(|_| {
        seen += 1;
        if seen == 2 {
            Err(credential_source::CredentialSourceError::Format(
                "injected replay crash".into(),
            ))
        } else {
            Ok(())
        }
    });
    tests.push(SecurityResult {
        name: "crash_during_replay",
        passed: injected_abort.is_err()
            && CredentialSourceReader::open(source, provider, &expected).is_ok(),
    });
    tests.push(SecurityResult {
        name: "cleanup_after_abort",
        passed: !results
            .read_dir()?
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains(".tmp-")),
    });
    Ok(tests)
}

fn fixture_equal(left: &RelationFixture, right: &RelationFixture) -> bool {
    left.a == right.a
        && left.b == right.b
        && left.c == right.c
        && left.vars == right.vars
        && left.inputs == right.inputs
}

fn fixture_digest(fixture: &RelationFixture) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"thinwallet/relation-layout/v1");
    for matrix in [&fixture.a, &fixture.b, &fixture.c] {
        digest.update((matrix.len() as u64).to_be_bytes());
        for (row, column, value) in matrix {
            digest.update((*row as u64).to_be_bytes());
            digest.update((*column as u64).to_be_bytes());
            digest.update(value);
        }
    }
    for vector in [&fixture.vars, &fixture.inputs] {
        digest.update((vector.len() as u64).to_be_bytes());
        for value in vector {
            digest.update(value);
        }
    }
    digest.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
