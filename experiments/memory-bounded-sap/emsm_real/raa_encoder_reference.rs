// Rust interface mirror for Phase 2A. See raa_encoder_reference.py.

pub trait ReferenceRaaEncoder<Fr> {
    fn encode(&self) -> Result<Vec<Fr>, String>;
}

