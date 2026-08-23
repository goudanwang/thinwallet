// Rust interface mirror for Phase 2B local integrity checks.

pub enum HIntegrityError {
    WrongMagic,
    WrongVersion,
    DigestMismatch,
    RollbackDetected,
    TruncatedFile,
}

