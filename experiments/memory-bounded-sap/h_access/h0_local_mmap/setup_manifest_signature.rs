// Rust interface mirror for setup manifest signatures.

pub struct SetupManifestSignature {
    pub authority_id: String,
    pub signature_scheme: String,
    pub signature_bytes: Vec<u8>,
}

