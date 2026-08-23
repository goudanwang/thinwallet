// Rust interface mirror for Phase 2C setup check verifier.

pub enum SetupCheckMode {
    SignedOnly,
    RandomCheckOnInstall,
    FullVerifyOnInstall,
    SignedPlusRandomCheck,
}

