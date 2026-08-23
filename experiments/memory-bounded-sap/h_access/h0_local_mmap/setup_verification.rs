// Rust interface mirror for setup verification result.

pub enum SetupVerificationResult {
    FullyVerified,
    SignedPreverified,
    ProbabilisticallyChecked,
    CorrectnessAssumed,
}

