use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use libspartan_patched::multi_state_store::{
    MultiObjectFileBackedStateStore, MultiObjectStoreConfig, ProverStateStore, StateDurability,
};
use preprocessed_pbmo::{
    RelationShape, SoftwareCrashConsistentProvider, SoftwareTokenStoreKeyProvider, Token,
    TokenBinding, TokenState, TokenStore, BACKEND_REVISION,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::fs;

fn open_token_store(root: &std::path::Path) -> TokenStore {
    TokenStore::open(
        root,
        Box::new(SoftwareTokenStoreKeyProvider::new(
            "software-test-key-v1",
            [0x31; 32],
        )),
        Box::new(SoftwareCrashConsistentProvider),
        [0x42; 32],
    )
    .unwrap()
}

#[test]
fn deleting_spill_state_never_restores_a_reserved_pbmo_token() {
    let root =
        std::env::temp_dir().join(format!("thinwallet-section4-token-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let token_root = root.join("tokens");
    let spill_root = root.join("spill");
    let binding = TokenBinding {
        basis_digest: [0x11; 32],
        backend_revision: BACKEND_REVISION.to_owned(),
        relation_shape: RelationShape {
            relation_id: "section4-test".to_owned(),
            logical_commitment_id: "section4-logical".to_owned(),
            layout_version: "v1".to_owned(),
        },
        q: 1,
        m: 1,
    };
    let token = Token::generate_with_material(
        binding.clone(),
        &[RISTRETTO_BASEPOINT_POINT],
        [0x21; 16],
        [0x22; 32],
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(7);
    let mut tokens = open_token_store(&token_root);
    tokens.insert(&token, &mut rng).unwrap();
    tokens
        .reserve(
            &token.token_id,
            &binding,
            binding.context_digest(),
            "section4-session",
            "section4-invocation",
            [0x61; 32],
            &mut rng,
        )
        .unwrap();
    assert_eq!(tokens.state(&token.token_id), Some(TokenState::Reserved));

    let mut spill = MultiObjectFileBackedStateStore::create(MultiObjectStoreConfig {
        root: spill_root,
        proof_session: "independent-spill".to_owned(),
        backend_revision: "section4-test".to_owned(),
        metadata_key: [0x51; 32],
        maximum_chunk_bytes: 64,
        maximum_temporary_storage_bytes: 1024,
        durability: StateDurability::SecurityCriticalDurable,
    })
    .unwrap();
    spill.abort_session_cleanup().unwrap();
    assert_eq!(tokens.state(&token.token_id), Some(TokenState::Reserved));
    drop(tokens);

    let recovered = open_token_store(&token_root);
    assert_eq!(recovered.state(&token.token_id), Some(TokenState::Burned));
    assert_ne!(
        recovered.state(&token.token_id),
        Some(TokenState::Available)
    );
    fs::remove_dir_all(root).unwrap();
}
