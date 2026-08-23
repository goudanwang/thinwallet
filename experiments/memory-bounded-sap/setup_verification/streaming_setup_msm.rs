// Rust interface mirror for Phase 2C streaming setup MSM equality.

pub trait StreamingSetupMsm {
    fn check(&mut self) -> Result<bool, String>;
}

