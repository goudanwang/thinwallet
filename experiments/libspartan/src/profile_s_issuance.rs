use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
const CREDENTIAL_DOMAIN: &[u8] = b"THINWALLET-PROFILE-S-CREDENTIAL-V1";
const REVOCATION_DOMAIN: &[u8] = b"THINWALLET-PROFILE-S-REVOCATION-V1";
const PACKAGE_MAGIC: &[u8; 8] = b"TWCSCRD1";
const PACKAGE_LEN: usize = 8 + 2 + 8 + 8 + 32 + 32 + 8 + 64 + 7 * 8 + 32;

#[derive(Debug, Error)]
pub enum ProfileSError {
    #[error("non-canonical credential package")]
    NonCanonicalPackage,
    #[error("malformed public key")]
    MalformedPublicKey,
    #[error("malformed signature")]
    MalformedSignature,
    #[error("unknown issuer public-key identifier")]
    UnknownIssuerKey,
    #[error("issuer identity does not match registry entry")]
    WrongIssuer,
    #[error("strict signature verification failed")]
    InvalidSignature,
    #[error("wrong registry identity")]
    WrongRegistry,
    #[error("revocation statement is stale")]
    StaleEpoch,
    #[error("revocation statement epoch is in the future")]
    FutureEpoch,
    #[error("revocation statement is not yet valid")]
    FutureValidity,
    #[error("revocation statement has expired")]
    ExpiredValidity,
    #[error("credential type does not match")]
    WrongCredentialType,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrivateCredentialFields {
    pub credential_id: u64,
    pub holder_secret: u64,
    pub age: u64,
    pub country: u64,
    pub expiry: u64,
    pub revocation_id: u64,
    pub schema_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialPackage {
    pub protocol_version: u16,
    pub credential_type: u64,
    pub issuer_id: u64,
    pub issuer_public_key_id: [u8; 32],
    pub credential_commitment: [u8; 32],
    pub issuance_epoch: u64,
    pub signature: [u8; 64],
    pub private_fields: PrivateCredentialFields,
    pub commitment_salt: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedCredentialStatement {
    pub protocol_version: u16,
    pub credential_type: u64,
    pub issuer_id: u64,
    pub issuer_public_key_id: [u8; 32],
    pub credential_commitment: [u8; 32],
    pub issuance_epoch: u64,
}

#[derive(Clone)]
struct IssuerEntry {
    issuer_id: u64,
    key: VerifyingKey,
}

#[derive(Default)]
pub struct IssuerRegistry {
    entries: BTreeMap<[u8; 32], IssuerEntry>,
}

impl IssuerRegistry {
    pub fn register(
        &mut self,
        issuer_id: u64,
        key_bytes: [u8; 32],
    ) -> Result<[u8; 32], ProfileSError> {
        let key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| ProfileSError::MalformedPublicKey)?;
        if key.is_weak() {
            return Err(ProfileSError::MalformedPublicKey);
        }
        let key_id = public_key_id(&key_bytes);
        self.entries.insert(key_id, IssuerEntry { issuer_id, key });
        Ok(key_id)
    }

    pub fn verify_package(
        &self,
        package: &CredentialPackage,
    ) -> Result<VerifiedCredentialStatement, ProfileSError> {
        let entry = self
            .entries
            .get(&package.issuer_public_key_id)
            .ok_or(ProfileSError::UnknownIssuerKey)?;
        if entry.issuer_id != package.issuer_id {
            return Err(ProfileSError::WrongIssuer);
        }
        let signature = Signature::from_slice(&package.signature)
            .map_err(|_| ProfileSError::MalformedSignature)?;
        let message = credential_signature_message(
            package.protocol_version,
            package.credential_type,
            &package.credential_commitment,
            package.issuance_epoch,
        );
        entry
            .key
            .verify_strict(&message, &signature)
            .map_err(|_| ProfileSError::InvalidSignature)?;
        Ok(VerifiedCredentialStatement {
            protocol_version: package.protocol_version,
            credential_type: package.credential_type,
            issuer_id: package.issuer_id,
            issuer_public_key_id: package.issuer_public_key_id,
            credential_commitment: package.credential_commitment,
            issuance_epoch: package.issuance_epoch,
        })
    }
}

pub fn public_key_id(key: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(key).into()
}

pub fn credential_signature_message(
    protocol_version: u16,
    credential_type: u64,
    commitment: &[u8; 32],
    issuance_epoch: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(CREDENTIAL_DOMAIN.len() + 2 + 8 + 32 + 8);
    message.extend_from_slice(CREDENTIAL_DOMAIN);
    message.extend_from_slice(&protocol_version.to_be_bytes());
    message.extend_from_slice(&credential_type.to_be_bytes());
    message.extend_from_slice(commitment);
    message.extend_from_slice(&issuance_epoch.to_be_bytes());
    message
}

pub fn issue_package(
    signing_key: &SigningKey,
    credential_type: u64,
    issuer_id: u64,
    credential_commitment: [u8; 32],
    issuance_epoch: u64,
    private_fields: PrivateCredentialFields,
    commitment_salt: [u8; 32],
) -> CredentialPackage {
    let verifying_key = signing_key.verifying_key().to_bytes();
    let message = credential_signature_message(
        PROTOCOL_VERSION,
        credential_type,
        &credential_commitment,
        issuance_epoch,
    );
    let signature = signing_key.sign(&message).to_bytes();
    CredentialPackage {
        protocol_version: PROTOCOL_VERSION,
        credential_type,
        issuer_id,
        issuer_public_key_id: public_key_id(&verifying_key),
        credential_commitment,
        issuance_epoch,
        signature,
        private_fields,
        commitment_salt,
    }
}

pub fn encode_package(package: &CredentialPackage) -> Vec<u8> {
    let mut out = Vec::with_capacity(PACKAGE_LEN);
    out.extend_from_slice(PACKAGE_MAGIC);
    out.extend_from_slice(&package.protocol_version.to_be_bytes());
    out.extend_from_slice(&package.credential_type.to_be_bytes());
    out.extend_from_slice(&package.issuer_id.to_be_bytes());
    out.extend_from_slice(&package.issuer_public_key_id);
    out.extend_from_slice(&package.credential_commitment);
    out.extend_from_slice(&package.issuance_epoch.to_be_bytes());
    out.extend_from_slice(&package.signature);
    for value in [
        package.private_fields.credential_id,
        package.private_fields.holder_secret,
        package.private_fields.age,
        package.private_fields.country,
        package.private_fields.expiry,
        package.private_fields.revocation_id,
        package.private_fields.schema_id,
    ] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&package.commitment_salt);
    out
}

pub fn decode_package(bytes: &[u8]) -> Result<CredentialPackage, ProfileSError> {
    if bytes.len() != PACKAGE_LEN || &bytes[..8] != PACKAGE_MAGIC {
        return Err(ProfileSError::NonCanonicalPackage);
    }
    let mut cursor = 8;
    let u16_at = |offset: &mut usize| {
        let value = u16::from_be_bytes(
            bytes[*offset..*offset + 2]
                .try_into()
                .expect("fixed package"),
        );
        *offset += 2;
        value
    };
    let u64_at = |offset: &mut usize| {
        let value = u64::from_be_bytes(
            bytes[*offset..*offset + 8]
                .try_into()
                .expect("fixed package"),
        );
        *offset += 8;
        value
    };
    let protocol_version = u16_at(&mut cursor);
    let credential_type = u64_at(&mut cursor);
    let issuer_id = u64_at(&mut cursor);
    let issuer_public_key_id = bytes[cursor..cursor + 32]
        .try_into()
        .expect("fixed package");
    cursor += 32;
    let credential_commitment = bytes[cursor..cursor + 32]
        .try_into()
        .expect("fixed package");
    cursor += 32;
    let issuance_epoch = u64_at(&mut cursor);
    let signature = bytes[cursor..cursor + 64]
        .try_into()
        .expect("fixed package");
    cursor += 64;
    let private_fields = PrivateCredentialFields {
        credential_id: u64_at(&mut cursor),
        holder_secret: u64_at(&mut cursor),
        age: u64_at(&mut cursor),
        country: u64_at(&mut cursor),
        expiry: u64_at(&mut cursor),
        revocation_id: u64_at(&mut cursor),
        schema_id: u64_at(&mut cursor),
    };
    let commitment_salt = bytes[cursor..cursor + 32]
        .try_into()
        .expect("fixed package");
    if curve25519_dalek::scalar::Scalar::from_canonical_bytes(credential_commitment)
        .is_none()
        .into()
        || curve25519_dalek::scalar::Scalar::from_canonical_bytes(commitment_salt)
            .is_none()
            .into()
    {
        return Err(ProfileSError::NonCanonicalPackage);
    }
    Ok(CredentialPackage {
        protocol_version,
        credential_type,
        issuer_id,
        issuer_public_key_id,
        credential_commitment,
        issuance_epoch,
        signature,
        private_fields,
        commitment_salt,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevocationStatement {
    pub protocol_version: u16,
    pub registry_id: u64,
    pub credential_type: u64,
    pub sparse_merkle_root: [u8; 32],
    pub epoch: u64,
    pub valid_from: u64,
    pub valid_until: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRevocationStatement {
    pub statement: RevocationStatement,
    pub signature: [u8; 64],
}

pub fn revocation_message(statement: &RevocationStatement) -> Vec<u8> {
    let mut message = Vec::with_capacity(REVOCATION_DOMAIN.len() + 2 + 8 * 5 + 32);
    message.extend_from_slice(REVOCATION_DOMAIN);
    message.extend_from_slice(&statement.protocol_version.to_be_bytes());
    message.extend_from_slice(&statement.registry_id.to_be_bytes());
    message.extend_from_slice(&statement.credential_type.to_be_bytes());
    message.extend_from_slice(&statement.sparse_merkle_root);
    message.extend_from_slice(&statement.epoch.to_be_bytes());
    message.extend_from_slice(&statement.valid_from.to_be_bytes());
    message.extend_from_slice(&statement.valid_until.to_be_bytes());
    message
}

pub fn sign_revocation(
    signing_key: &SigningKey,
    statement: RevocationStatement,
) -> SignedRevocationStatement {
    let signature = signing_key.sign(&revocation_message(&statement)).to_bytes();
    SignedRevocationStatement {
        statement,
        signature,
    }
}

pub fn verify_revocation(
    verifying_key: &VerifyingKey,
    signed: &SignedRevocationStatement,
    expected_registry: u64,
    expected_type: u64,
    minimum_epoch: u64,
    maximum_epoch: u64,
    now: u64,
) -> Result<(), ProfileSError> {
    if verifying_key.is_weak() {
        return Err(ProfileSError::MalformedPublicKey);
    }
    if signed.statement.registry_id != expected_registry {
        return Err(ProfileSError::WrongRegistry);
    }
    if signed.statement.credential_type != expected_type {
        return Err(ProfileSError::WrongCredentialType);
    }
    if signed.statement.epoch < minimum_epoch {
        return Err(ProfileSError::StaleEpoch);
    }
    if signed.statement.epoch > maximum_epoch {
        return Err(ProfileSError::FutureEpoch);
    }
    if now < signed.statement.valid_from {
        return Err(ProfileSError::FutureValidity);
    }
    if now > signed.statement.valid_until {
        return Err(ProfileSError::ExpiredValidity);
    }
    let signature =
        Signature::from_slice(&signed.signature).map_err(|_| ProfileSError::MalformedSignature)?;
    verifying_key
        .verify_strict(&revocation_message(&signed.statement), &signature)
        .map_err(|_| ProfileSError::InvalidSignature)
}
