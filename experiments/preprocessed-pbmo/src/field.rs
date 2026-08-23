use crate::{Scalar, PROTOCOL_VERSION};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::time::Instant;

type HmacSha512 = Hmac<Sha512>;

/// All public metadata bound into one mask scalar derivation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DomainMetadata {
    pub token_id: [u8; 16],
    pub basis_digest: [u8; 32],
    pub backend_revision: String,
    pub logical_commitment_id: String,
    pub relation_shape: String,
    pub q: u32,
    pub m: u32,
}

fn put_len_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

fn mask_input(meta: &DomainMetadata, row: u32, col: u32, counter: u64) -> Vec<u8> {
    let mut input = Vec::with_capacity(192);
    put_len_bytes(&mut input, b"thinwallet/preprocessed-pbmo/mask-to-field");
    input.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    input.extend_from_slice(&meta.token_id);
    input.extend_from_slice(&meta.basis_digest);
    put_len_bytes(&mut input, meta.backend_revision.as_bytes());
    put_len_bytes(&mut input, meta.logical_commitment_id.as_bytes());
    put_len_bytes(&mut input, meta.relation_shape.as_bytes());
    input.extend_from_slice(&meta.q.to_le_bytes());
    input.extend_from_slice(&meta.m.to_le_bytes());
    input.extend_from_slice(&row.to_le_bytes());
    input.extend_from_slice(&col.to_le_bytes());
    input.extend_from_slice(&counter.to_le_bytes());
    input
}

/// Derive a Ristretto scalar using HMAC-SHA-512 followed by 512-bit wide
/// reduction. The distance from uniform is below 2^-259 for this field/order
/// ratio and 512-bit source; no unchecked 32-byte modular map is used.
pub fn derive_mask_scalar(
    seed: &[u8; 32],
    meta: &DomainMetadata,
    row: u32,
    col: u32,
    counter: u64,
) -> Scalar {
    let mut mac = HmacSha512::new_from_slice(seed).expect("HMAC accepts 32-byte keys");
    mac.update(&mask_input(meta, row, col, counter));
    let digest = mac.finalize().into_bytes();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

pub(crate) fn derive_mask_scalar_profiled(
    seed: &[u8; 32],
    meta: &DomainMetadata,
    row: u32,
    col: u32,
    counter: u64,
) -> (Scalar, u64, u64) {
    let prf_started = Instant::now();
    let mut mac = HmacSha512::new_from_slice(seed).expect("HMAC accepts 32-byte keys");
    mac.update(&mask_input(meta, row, col, counter));
    let digest = mac.finalize().into_bytes();
    let prf_ns = prf_started.elapsed().as_nanos() as u64;
    let reduction_started = Instant::now();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    let reduction_ns = reduction_started.elapsed().as_nanos() as u64;
    (scalar, prf_ns, reduction_ns)
}

/// Hash public server outputs and the bound transcript to an unpredictable
/// post-commitment batch-check challenge.
pub fn derive_batch_challenge(
    transcript: &[u8],
    token_id: &[u8; 16],
    output_digest: &[u8; 32],
    row: u32,
) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"thinwallet/preprocessed-pbmo/batch-check/v2");
    h.update(PROTOCOL_VERSION.to_le_bytes());
    h.update((transcript.len() as u64).to_le_bytes());
    h.update(transcript);
    h.update(token_id);
    h.update(output_digest);
    h.update(row.to_le_bytes());
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

pub(crate) fn digest32(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((domain.len() as u32).to_le_bytes());
    h.update(domain);
    for part in parts {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> DomainMetadata {
        DomainMetadata {
            token_id: [1; 16],
            basis_digest: [2; 32],
            backend_revision: "backend-a".into(),
            logical_commitment_id: "witness".into(),
            relation_shape: "shape-a".into(),
            q: 8,
            m: 16,
        }
    }

    #[test]
    fn deterministic_and_separated() {
        let seed = [7; 32];
        let meta = metadata();
        assert_eq!(
            derive_mask_scalar(&seed, &meta, 3, 4, 0),
            derive_mask_scalar(&seed, &meta, 3, 4, 0)
        );
        let mut other = meta.clone();
        other.token_id[0] ^= 1;
        assert_ne!(
            derive_mask_scalar(&seed, &meta, 3, 4, 0),
            derive_mask_scalar(&seed, &other, 3, 4, 0)
        );
        other = meta.clone();
        other.basis_digest[0] ^= 1;
        assert_ne!(
            derive_mask_scalar(&seed, &meta, 3, 4, 0),
            derive_mask_scalar(&seed, &other, 3, 4, 0)
        );
        other = meta.clone();
        other.q += 1;
        assert_ne!(
            derive_mask_scalar(&seed, &meta, 3, 4, 0),
            derive_mask_scalar(&seed, &other, 3, 4, 0)
        );
    }
}
