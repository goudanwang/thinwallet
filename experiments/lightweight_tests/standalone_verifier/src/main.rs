use anyhow::{anyhow, Context, Result};
use libspartan_baseline as baseline;
use merlin::Transcript;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[path = "../../../libspartan/src/credential_source/mod.rs"]
mod credential_source;
#[path = "../../../libspartan/src/credential_workloads.rs"]
mod credential_workloads;

use credential_workloads::profile_s::{ProfileSReplayRecord, ProfileSWorkload};

const TRANSCRIPT_LABEL: &[u8] = b"thinwallet_phase_v2_pbmo_fixed";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn value(bytes: &[u8; 32]) -> Result<u64> {
    if bytes[8..].iter().any(|byte| *byte != 0) {
        return Err(anyhow!("fixture integer exceeds u64"));
    }
    let mut lower = [0u8; 8];
    lower.copy_from_slice(&bytes[..8]);
    Ok(u64::from_le_bytes(lower))
}

fn load_fixture(source: &Path, workload: ProfileSWorkload) -> Result<credential_workloads::RelationFixture> {
    let provider = credential_source::SoftwareCredentialSourceKeyProvider::new(
        "thinwallet-v4e-software-key-1",
        [0x5au8; 32],
    );
    let reader = credential_source::CredentialSourceReader::open_authenticated(source, &provider)
        .map_err(|error| anyhow!(error.to_string()))?;
    let header = reader.header();
    let ProfileSWorkload::WK {
        credentials,
        revocation_count,
        revocation_depth,
        revocation_backend,
    } = workload
    else {
        return Err(anyhow!("standalone verifier supports Profile S WK only"));
    };
    if header.credential_count != credentials as u32
        || header.revocation_count != revocation_count as u32
        || header.revocation_depth != revocation_depth as u32
        || header.revocation_backend != revocation_backend.label()
        || header.revocation_set != (0..revocation_count as u32).collect::<Vec<_>>()
        || header.backend_revision != "libspartan-0.9.0-thinwallet-fs7"
    {
        return Err(anyhow!("credential source workload/backend mismatch"));
    }
    let expected_root = if revocation_count == 0 {
        [0; 32]
    } else {
        credential_workloads::profile_s::fixture_revocation_material(
            revocation_count,
            0,
            revocation_depth,
        )
        .1
    };
    if header.registry_root != expected_root || header.registry_epoch != 73 {
        return Err(anyhow!("credential source registry mismatch"));
    }

    let mut replay = Vec::with_capacity(credentials);
    reader
        .for_each_record(|record| {
            if record.hidden_attributes.len() != 4
                || record.signed_credential_commitment.len() != 32
            {
                return Err(credential_source::CredentialSourceError::Format(
                    "Profile S replay field count mismatch".into(),
                ));
            }
            let mut expected_commitment = [0u8; 32];
            expected_commitment.copy_from_slice(&record.signed_credential_commitment);
            replay.push(ProfileSReplayRecord {
                credential_type: record.credential_type,
                issuer_id: record.issuer_id,
                credential_id: value(&record.hidden_attributes[0]).map_err(|error| {
                    credential_source::CredentialSourceError::Format(error.to_string())
                })?,
                holder_secret: value(&record.holder_binding).map_err(|error| {
                    credential_source::CredentialSourceError::Format(error.to_string())
                })?,
                schema_id: value(&record.hidden_attributes[1]).map_err(|error| {
                    credential_source::CredentialSourceError::Format(error.to_string())
                })?,
                age: value(&record.hidden_attributes[2]).map_err(|error| {
                    credential_source::CredentialSourceError::Format(error.to_string())
                })?,
                country: value(&record.hidden_attributes[3]).map_err(|error| {
                    credential_source::CredentialSourceError::Format(error.to_string())
                })?,
                expiry: record.expiry,
                revocation_id: record.revocation_identifier,
                issuance_epoch: record.issuance_epoch,
                salt: record.commitment_salt,
                issuer_key_digest: record.issuer_public_key_digest,
                expected_commitment,
                revocation_path: record.revocation_witness.clone(),
            });
            Ok(())
        })
        .map_err(|error| anyhow!(error.to_string()))?;

    let fixture = credential_workloads::profile_s::build_profile_s_from_records(
        workload,
        1usize << 18,
        &replay,
    )
    .map_err(|error| anyhow!(error))?;
    let input_refs = fixture
        .inputs
        .iter()
        .map(|input| input.as_slice())
        .collect::<Vec<_>>();
    let source_input_digest = credential_source::digest_bytes(
        b"thinwallet/public-inputs/v1",
        &input_refs,
    );
    if source_input_digest != header.public_input_digest {
        return Err(anyhow!("reconstructed public inputs do not match source header"));
    }
    Ok(fixture)
}

fn verify_one(
    proof_path: &Path,
    commitment: &baseline::ComputationCommitment,
    inputs: &baseline::InputsAssignment,
    gens: &baseline::SNARKGens,
    public_input_sha256: &str,
) {
    let run_id = proof_path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .unwrap_or("UNKNOWN");
    let result = (|| -> Result<(String, bool)> {
        let proof_bytes = fs::read(proof_path).context("read proof")?;
        let proof_sha256 = sha256(&proof_bytes);
        let proof: baseline::SNARK = bincode::deserialize(&proof_bytes)
            .context("deserialize proof with vendored baseline")?;
        let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
        let accepted = proof
            .verify(commitment, inputs, &mut transcript, gens)
            .is_ok();
        Ok((proof_sha256, accepted))
    })();
    match result {
        Ok((proof_sha256, accepted)) => println!(
            "{run_id}\t{proof_sha256}\t{public_input_sha256}\t{}\t",
            if accepted { "PASS" } else { "FAIL" }
        ),
        Err(error) => println!(
            "{run_id}\tMISSING\t{public_input_sha256}\tERROR\t{}",
            error.to_string().replace(['\t', '\n'], " ")
        ),
    }
}

fn main() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let workload_name = args
        .next()
        .ok_or_else(|| anyhow!("usage: standalone-verifier WORKLOAD SOURCE PROOF..."))?;
    let source = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow!("missing credential source"))?,
    );
    let proof_paths = args.map(PathBuf::from).collect::<Vec<_>>();
    if proof_paths.is_empty() {
        return Err(anyhow!("no proof paths supplied"));
    }
    let workload_name = workload_name
        .to_str()
        .ok_or_else(|| anyhow!("workload is not UTF-8"))?;
    let workload = ProfileSWorkload::parse(workload_name)
        .ok_or_else(|| anyhow!("unknown workload {workload_name}"))?;
    let fixture = load_fixture(&source, workload)?;
    let n = 1usize << 18;
    let num_inputs = fixture.inputs.len();
    let num_nz_entries = fixture.a.len().max(fixture.b.len()).max(fixture.c.len());
    let instance = baseline::Instance::new(
        n,
        n,
        num_inputs,
        &fixture.a,
        &fixture.b,
        &fixture.c,
    )
    .map_err(|error| anyhow!(format!("{error:?}")))?;
    let inputs = baseline::InputsAssignment::new(&fixture.inputs)
        .map_err(|error| anyhow!(format!("{error:?}")))?;
    let gens = baseline::SNARKGens::new(n, n, num_inputs, num_nz_entries);
    let (commitment, _) = baseline::SNARK::encode(&instance, &gens);
    let public_input_sha256 = sha256(&fixture.inputs.concat());
    eprintln!(
        "standalone baseline ready workload={workload_name} public_inputs={} public_input_sha256={public_input_sha256}",
        fixture.inputs.len()
    );
    for proof_path in proof_paths {
        verify_one(
            &proof_path,
            &commitment,
            &inputs,
            &gens,
            &public_input_sha256,
        );
    }
    Ok(())
}
