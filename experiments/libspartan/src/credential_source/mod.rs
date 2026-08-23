#![allow(dead_code)]

use bincode::Options;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Sha3_512;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"TWCSRC01";
const FORMAT_VERSION: u16 = 1;
const DOMAIN: &[u8] = b"thinwallet/credential-source/v1";
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_CREDENTIALS: usize = 1 << 20;

type SourcePrefix = (String, [u8; 24], Vec<u8>, BufReader<File>);

#[derive(Debug, Error)]
pub enum CredentialSourceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("credential source authentication failed")]
    Authentication,
    #[error("credential source encoding failed: {0}")]
    Encoding(String),
    #[error("credential source format is invalid: {0}")]
    Format(String),
    #[error("credential source binding mismatch: {0}")]
    Binding(&'static str),
    #[error("credential source key is unavailable: {0}")]
    Key(String),
    #[error("credential source rollback detected")]
    Rollback,
}

pub trait CredentialSourceKeyProvider {
    fn key(&self, key_id: &str) -> Result<[u8; 32], CredentialSourceError>;
}

#[derive(Clone)]
pub struct SoftwareCredentialSourceKeyProvider {
    key_id: String,
    key: [u8; 32],
}

impl SoftwareCredentialSourceKeyProvider {
    pub fn new(key_id: impl Into<String>, key: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            key,
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl CredentialSourceKeyProvider for SoftwareCredentialSourceKeyProvider {
    fn key(&self, key_id: &str) -> Result<[u8; 32], CredentialSourceError> {
        if key_id == self.key_id {
            Ok(self.key)
        } else {
            Err(CredentialSourceError::Key(key_id.to_owned()))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialSourceHeader {
    pub source_format_version: u16,
    pub protocol_version: String,
    pub backend_revision: String,
    pub relation_layout_digest: [u8; 32],
    pub proof_session_id: [u8; 32],
    pub credential_count: u32,
    pub revocation_count: u32,
    pub revocation_depth: u32,
    pub revocation_backend: String,
    pub revocation_set: Vec<u32>,
    pub registry_id: String,
    pub registry_root: [u8; 32],
    pub registry_epoch: u64,
    pub public_input_digest: [u8; 32],
    pub source_generation: u64,
    pub source_length: u64,
    pub source_digest: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialSourceRecord {
    pub credential_index: u32,
    pub credential_package_digest: [u8; 32],
    pub issuer_id: u64,
    pub issuer_public_key_digest: [u8; 32],
    pub credential_type: u64,
    pub signed_credential_commitment: Vec<u8>,
    pub issuance_epoch: u64,
    pub commitment_salt: [u8; 32],
    pub hidden_attributes: Vec<[u8; 32]>,
    pub disclosed_attribute_bindings: Vec<[u8; 32]>,
    pub holder_binding: [u8; 32],
    pub expiry: u64,
    pub revocation_identifier: u64,
    pub predicate_parameters: Vec<[u8; 32]>,
    pub revocation_policy: bool,
    pub leaf_value: Option<[u8; 32]>,
    pub path_index: Option<u64>,
    pub revocation_witness: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct ExpectedCredentialSourceBinding {
    pub protocol_version: String,
    pub backend_revision: String,
    pub relation_layout_digest: [u8; 32],
    pub proof_session_id: [u8; 32],
    pub credential_count: u32,
    pub revocation_count: u32,
    pub revocation_depth: u32,
    pub revocation_backend: String,
    pub revocation_set: Vec<u32>,
    pub registry_id: String,
    pub registry_root: [u8; 32],
    pub registry_epoch: u64,
    pub public_input_digest: [u8; 32],
}

impl ExpectedCredentialSourceBinding {
    pub fn from_header(header: &CredentialSourceHeader) -> Self {
        Self {
            protocol_version: header.protocol_version.clone(),
            backend_revision: header.backend_revision.clone(),
            relation_layout_digest: header.relation_layout_digest,
            proof_session_id: header.proof_session_id,
            credential_count: header.credential_count,
            revocation_count: header.revocation_count,
            revocation_depth: header.revocation_depth,
            revocation_backend: header.revocation_backend.clone(),
            revocation_set: header.revocation_set.clone(),
            registry_id: header.registry_id.clone(),
            registry_root: header.registry_root,
            registry_epoch: header.registry_epoch,
            public_input_digest: header.public_input_digest,
        }
    }
}

pub struct CredentialSourceWriter;

impl CredentialSourceWriter {
    pub fn write<R: RngCore>(
        destination: &Path,
        key_id: &str,
        provider: &dyn CredentialSourceKeyProvider,
        mut header: CredentialSourceHeader,
        records: &[CredentialSourceRecord],
        rng: &mut R,
    ) -> Result<CredentialSourceHeader, CredentialSourceError> {
        validate_records(&header, records)?;
        header.source_format_version = FORMAT_VERSION;
        let record_bytes = records
            .iter()
            .map(canonical_encode)
            .collect::<Result<Vec<_>, _>>()?;
        header.source_length = record_bytes.iter().map(|bytes| bytes.len() as u64).sum();
        header.source_digest = source_digest(&header, &record_bytes)?;

        let key = provider.key(key_id)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let mut base_nonce = [0u8; 24];
        rng.fill_bytes(&mut base_nonce);
        let header_bytes = canonical_encode(&header)?;
        let encrypted_header = encrypt(&cipher, &base_nonce, 0, header_aad(), &header_bytes)?;

        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let temporary = temporary_path(destination, &base_nonce);
        let result = (|| {
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            let mut output = BufWriter::new(file);
            output.write_all(MAGIC)?;
            output.write_all(&FORMAT_VERSION.to_be_bytes())?;
            write_len(&mut output, key_id.len())?;
            output.write_all(key_id.as_bytes())?;
            output.write_all(&base_nonce)?;
            write_frame(&mut output, &encrypted_header)?;
            for (index, plaintext) in record_bytes.iter().enumerate() {
                let aad = record_aad(&header.source_digest, index as u32);
                let ciphertext = encrypt(&cipher, &base_nonce, index as u64 + 1, &aad, plaintext)?;
                write_frame(&mut output, &ciphertext)?;
            }
            output.flush()?;
            output.get_ref().sync_all()?;
            drop(output);
            fs::rename(&temporary, destination)?;
            sync_parent(parent)?;
            Ok::<_, CredentialSourceError>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        Ok(header)
    }
}

pub struct CredentialSourceReader {
    path: PathBuf,
    key: [u8; 32],
    base_nonce: [u8; 24],
    header: CredentialSourceHeader,
}

impl CredentialSourceReader {
    pub fn open_authenticated(
        path: impl Into<PathBuf>,
        provider: &dyn CredentialSourceKeyProvider,
    ) -> Result<Self, CredentialSourceError> {
        let path = path.into();
        let (key_id, base_nonce, encrypted_header, _) = read_prefix(&path)?;
        let key = provider.key(&key_id)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let plaintext = decrypt(&cipher, &base_nonce, 0, header_aad(), &encrypted_header)?;
        let header: CredentialSourceHeader = canonical_decode(&plaintext)?;
        let reader = Self {
            path,
            key,
            base_nonce,
            header,
        };
        reader.validate_all()?;
        Ok(reader)
    }

    pub fn open(
        path: impl Into<PathBuf>,
        provider: &dyn CredentialSourceKeyProvider,
        expected: &ExpectedCredentialSourceBinding,
    ) -> Result<Self, CredentialSourceError> {
        let reader = Self::open_authenticated(path, provider)?;
        let header = &reader.header;
        validate_binding(header, expected)?;
        Ok(reader)
    }

    pub fn header(&self) -> &CredentialSourceHeader {
        &self.header
    }

    pub fn for_each_record<F>(&self, mut consumer: F) -> Result<(), CredentialSourceError>
    where
        F: FnMut(&CredentialSourceRecord) -> Result<(), CredentialSourceError>,
    {
        let (_, _, _, mut input) = read_prefix(&self.path)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        let mut digest_header = self.header.clone();
        digest_header.source_digest = [0; 32];
        digest_header.source_length = 0;
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(canonical_encode(&digest_header)?);
        let mut source_length = 0u64;
        for index in 0..self.header.credential_count {
            let ciphertext = read_frame(&mut input, MAX_RECORD_BYTES + 16)?;
            let aad = record_aad(&self.header.source_digest, index);
            let plaintext = decrypt(
                &cipher,
                &self.base_nonce,
                index as u64 + 1,
                &aad,
                &ciphertext,
            )?;
            let record: CredentialSourceRecord = canonical_decode(&plaintext)?;
            if record.credential_index != index {
                return Err(CredentialSourceError::Format(
                    "credential indices are not canonical".into(),
                ));
            }
            validate_record(&self.header, &record)?;
            digest.update((plaintext.len() as u64).to_be_bytes());
            digest.update(&plaintext);
            source_length += plaintext.len() as u64;
            consumer(&record)?;
        }
        let mut trailing = [0u8; 1];
        if input.read(&mut trailing)? != 0 {
            return Err(CredentialSourceError::Format(
                "extra credential record or trailing bytes".into(),
            ));
        }
        if source_length != self.header.source_length {
            return Err(CredentialSourceError::Format(
                "source length mismatch".into(),
            ));
        }
        let computed: [u8; 32] = digest.finalize().into();
        if computed != self.header.source_digest {
            return Err(CredentialSourceError::Authentication);
        }
        Ok(())
    }

    fn validate_all(&self) -> Result<(), CredentialSourceError> {
        self.for_each_record(|_| Ok(()))
    }
}

pub struct CredentialRelationReplay<'a>(pub &'a CredentialSourceReader);
pub struct CredentialWitnessReplay<'a>(pub &'a CredentialSourceReader);

impl CredentialRelationReplay<'_> {
    pub fn replay_digest(&self) -> Result<[u8; 32], CredentialSourceError> {
        replay_digest(self.0, b"relation")
    }
}

impl CredentialWitnessReplay<'_> {
    pub fn replay_digest(&self) -> Result<[u8; 32], CredentialSourceError> {
        replay_digest(self.0, b"witness")
    }
}

#[derive(Default)]
pub struct CredentialSourceJournal {
    latest_generation: Option<u64>,
    accepted: BTreeSet<[u8; 32]>,
}

impl CredentialSourceJournal {
    pub fn accept(&mut self, header: &CredentialSourceHeader) -> Result<(), CredentialSourceError> {
        if self
            .latest_generation
            .is_some_and(|generation| header.source_generation < generation)
        {
            return Err(CredentialSourceError::Rollback);
        }
        self.latest_generation = Some(
            self.latest_generation
                .unwrap_or_default()
                .max(header.source_generation),
        );
        self.accepted.insert(header.source_digest);
        Ok(())
    }
}

pub fn digest_bytes(domain: &[u8], values: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for value in values {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.finalize().into()
}

fn replay_digest(
    reader: &CredentialSourceReader,
    pass: &[u8],
) -> Result<[u8; 32], CredentialSourceError> {
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(pass);
    digest.update(reader.header.relation_layout_digest);
    reader.for_each_record(|record| {
        digest.update(canonical_encode(record)?);
        Ok(())
    })?;
    Ok(digest.finalize().into())
}

fn validate_records(
    header: &CredentialSourceHeader,
    records: &[CredentialSourceRecord],
) -> Result<(), CredentialSourceError> {
    if records.len() != header.credential_count as usize || records.len() > MAX_CREDENTIALS {
        return Err(CredentialSourceError::Format(
            "credential element count mismatch".into(),
        ));
    }
    let canonical_revset: Vec<_> = header
        .revocation_set
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if canonical_revset != header.revocation_set
        || canonical_revset.len() != header.revocation_count as usize
    {
        return Err(CredentialSourceError::Format(
            "RevSet is not canonical".into(),
        ));
    }
    for (index, record) in records.iter().enumerate() {
        if record.credential_index != index as u32 {
            return Err(CredentialSourceError::Format(
                "credential indices are not canonical".into(),
            ));
        }
        validate_record(header, record)?;
    }
    Ok(())
}

fn validate_record(
    header: &CredentialSourceHeader,
    record: &CredentialSourceRecord,
) -> Result<(), CredentialSourceError> {
    let scalar_is_canonical =
        |value: &[u8; 32]| bool::from(Scalar::from_canonical_bytes(*value).is_some());
    if !scalar_is_canonical(&record.commitment_salt)
        || !scalar_is_canonical(&record.holder_binding)
        || record
            .hidden_attributes
            .iter()
            .any(|value| !scalar_is_canonical(value))
        || record
            .disclosed_attribute_bindings
            .iter()
            .any(|value| !scalar_is_canonical(value))
        || record
            .predicate_parameters
            .iter()
            .any(|value| !scalar_is_canonical(value))
        || record
            .leaf_value
            .iter()
            .any(|value| !scalar_is_canonical(value))
        || record
            .revocation_witness
            .iter()
            .any(|value| !scalar_is_canonical(value))
    {
        return Err(CredentialSourceError::Format(
            "non-canonical scalar encoding".into(),
        ));
    }
    if credential_package_digest(record)? != record.credential_package_digest {
        return Err(CredentialSourceError::Authentication);
    }
    let selected = header
        .revocation_set
        .binary_search(&record.credential_index)
        .is_ok();
    if selected != record.revocation_policy {
        return Err(CredentialSourceError::Format(
            "record RevSet policy mismatch".into(),
        ));
    }
    if selected {
        if header.revocation_backend != "SparseMerkle"
            || record.leaf_value.is_none()
            || record.path_index != Some(record.revocation_identifier)
            || record.revocation_witness.len() != header.revocation_depth as usize
            || sparse_merkle_root(
                record.path_index.expect("checked above"),
                record.leaf_value.expect("checked above"),
                &record.revocation_witness,
            ) != header.registry_root
        {
            return Err(CredentialSourceError::Format(
                "incomplete or unbound revocation witness".into(),
            ));
        }
    } else if record.leaf_value.is_some()
        || record.path_index.is_some()
        || !record.revocation_witness.is_empty()
    {
        return Err(CredentialSourceError::Format(
            "unexpected revocation witness".into(),
        ));
    }
    Ok(())
}

pub fn credential_package_digest(
    record: &CredentialSourceRecord,
) -> Result<[u8; 32], CredentialSourceError> {
    let mut canonical = record.clone();
    canonical.credential_package_digest = [0; 32];
    Ok(digest_bytes(
        b"thinwallet/credential-package/v1",
        &[&canonical_encode(&canonical)?],
    ))
}

fn sparse_merkle_root(index: u64, leaf: [u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
    let mut current = Option::<Scalar>::from(Scalar::from_canonical_bytes(leaf))
        .expect("record scalar canonicality was validated");
    for (level, sibling) in path.iter().enumerate() {
        let sibling = Option::<Scalar>::from(Scalar::from_canonical_bytes(*sibling))
            .expect("record scalar canonicality was validated");
        current = if (index >> level) & 1 == 0 {
            source_native_hash(&[current, sibling], Scalar::ZERO, 0x4d45524b)
        } else {
            source_native_hash(&[sibling, current], Scalar::ZERO, 0x4d45524b)
        };
    }
    current.to_bytes()
}

fn source_round_constant(round: usize) -> Scalar {
    let mut hasher = Sha3_512::new();
    hasher.update(b"thinwallet-v4b-mimc7-ristretto255-v1");
    hasher.update((round as u64).to_le_bytes());
    Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
}

fn source_native_hash(blocks: &[Scalar], key: Scalar, domain: u64) -> Scalar {
    let mut state = Scalar::from(domain);
    for block in blocks {
        state += block;
        for round in 0..91 {
            let x = state + key + source_round_constant(round);
            let x2 = x * x;
            let x4 = x2 * x2;
            state = x4 * x2 * x;
        }
        state += key;
    }
    state
}

fn validate_binding(
    header: &CredentialSourceHeader,
    expected: &ExpectedCredentialSourceBinding,
) -> Result<(), CredentialSourceError> {
    if header.source_format_version != FORMAT_VERSION {
        return Err(CredentialSourceError::Binding("source format version"));
    }
    macro_rules! check {
        ($field:ident, $label:literal) => {
            if header.$field != expected.$field {
                return Err(CredentialSourceError::Binding($label));
            }
        };
    }
    check!(protocol_version, "protocol version");
    check!(backend_revision, "backend revision");
    check!(relation_layout_digest, "relation layout");
    check!(proof_session_id, "proof session");
    check!(credential_count, "credential count");
    check!(revocation_count, "revocation count");
    check!(revocation_depth, "revocation depth");
    check!(revocation_backend, "revocation backend");
    check!(revocation_set, "RevSet");
    check!(registry_id, "registry id");
    check!(registry_root, "registry root");
    check!(registry_epoch, "registry epoch");
    check!(public_input_digest, "public inputs");
    Ok(())
}

fn source_digest(
    header: &CredentialSourceHeader,
    records: &[Vec<u8>],
) -> Result<[u8; 32], CredentialSourceError> {
    let mut digest_header = header.clone();
    digest_header.source_digest = [0; 32];
    digest_header.source_length = 0;
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(canonical_encode(&digest_header)?);
    for encoded in records {
        digest.update((encoded.len() as u64).to_be_bytes());
        digest.update(encoded);
    }
    Ok(digest.finalize().into())
}

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
        .reject_trailing_bytes()
}

fn canonical_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CredentialSourceError> {
    canonical_options()
        .serialize(value)
        .map_err(|error| CredentialSourceError::Encoding(error.to_string()))
}

fn canonical_decode<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<T, CredentialSourceError> {
    canonical_options()
        .deserialize(bytes)
        .map_err(|error| CredentialSourceError::Encoding(error.to_string()))
}

fn header_aad() -> &'static [u8] {
    b"thinwallet/credential-source/header/v1"
}

fn record_aad(source_digest: &[u8; 32], index: u32) -> Vec<u8> {
    [DOMAIN, b"/record/", source_digest, &index.to_be_bytes()].concat()
}

fn derived_nonce(base: &[u8; 24], counter: u64) -> [u8; 24] {
    let mut nonce = *base;
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&nonce[16..]);
    nonce[16..].copy_from_slice(&(u64::from_be_bytes(tail) ^ counter).to_be_bytes());
    nonce
}

fn encrypt(
    cipher: &XChaCha20Poly1305,
    base_nonce: &[u8; 24],
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CredentialSourceError> {
    let nonce = derived_nonce(base_nonce, counter);
    cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CredentialSourceError::Authentication)
}

fn decrypt(
    cipher: &XChaCha20Poly1305,
    base_nonce: &[u8; 24],
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CredentialSourceError> {
    let nonce = derived_nonce(base_nonce, counter);
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CredentialSourceError::Authentication)
}

fn temporary_path(destination: &Path, nonce: &[u8; 24]) -> PathBuf {
    let suffix = nonce[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    destination.with_extension(format!("tmp-{suffix}"))
}

fn sync_parent(parent: &Path) -> Result<(), CredentialSourceError> {
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn write_len(output: &mut impl Write, length: usize) -> Result<(), CredentialSourceError> {
    let length = u32::try_from(length)
        .map_err(|_| CredentialSourceError::Format("frame too large".into()))?;
    output.write_all(&length.to_be_bytes())?;
    Ok(())
}

fn write_frame(output: &mut impl Write, bytes: &[u8]) -> Result<(), CredentialSourceError> {
    write_len(output, bytes.len())?;
    output.write_all(bytes)?;
    Ok(())
}

fn read_frame(input: &mut impl Read, maximum: usize) -> Result<Vec<u8>, CredentialSourceError> {
    let mut length = [0u8; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > maximum {
        return Err(CredentialSourceError::Format("frame exceeds limit".into()));
    }
    let mut bytes = vec![0u8; length];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_prefix(path: &Path) -> Result<SourcePrefix, CredentialSourceError> {
    let mut input = BufReader::new(File::open(path)?);
    let mut magic = [0u8; 8];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(CredentialSourceError::Format("bad magic".into()));
    }
    let mut version = [0u8; 2];
    input.read_exact(&mut version)?;
    if u16::from_be_bytes(version) != FORMAT_VERSION {
        return Err(CredentialSourceError::Binding("source format version"));
    }
    let mut key_id_length = [0u8; 4];
    input.read_exact(&mut key_id_length)?;
    let key_id_length = u32::from_be_bytes(key_id_length) as usize;
    if key_id_length > 1024 {
        return Err(CredentialSourceError::Format("key id too long".into()));
    }
    let mut key_id = vec![0u8; key_id_length];
    input.read_exact(&mut key_id)?;
    let key_id = String::from_utf8(key_id)
        .map_err(|_| CredentialSourceError::Format("key id is not UTF-8".into()))?;
    let mut nonce = [0u8; 24];
    input.read_exact(&mut nonce)?;
    let encrypted_header = read_frame(&mut input, MAX_HEADER_BYTES + 16)?;
    Ok((key_id, nonce, encrypted_header, input))
}
