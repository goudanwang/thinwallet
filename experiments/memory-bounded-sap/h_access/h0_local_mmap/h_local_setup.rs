// Rust interface mirror for Phase 2B local setup.

pub enum HSetupMode {
    IssuerIndependentPublicDownload,
    ApplicationPackageAsset,
    CdnDownload,
    ServerDownloadThenLocalVerification,
}

