use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use libspartan_patched::multi_state_store::{
    MultiObjectFileBackedStateStore, MultiObjectStoreConfig, ProverStateStore, StateDurability,
    StateObjectDescriptor,
};
use preprocessed_pbmo::{
    basis_digest, RelationShape, SoftwareCrashConsistentProvider, SoftwareTokenStoreKeyProvider,
    Token, TokenBinding, TokenState, TokenStore, BACKEND_REVISION,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn crash_during_ephemeral_spill_burns_reserved_token() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "thinwallet-v3d-crash-{}-{nonce}",
        std::process::id()
    ));
    let token_root = root.join("token");
    let spill_root = root.join("spill");
    let bases = (1u64..=4)
        .map(|value| RistrettoPoint::mul_base(&Scalar::from(value)))
        .collect::<Vec<_>>();
    let binding = TokenBinding {
        basis_digest: basis_digest(&bases),
        backend_revision: BACKEND_REVISION.into(),
        relation_shape: RelationShape {
            relation_id: "v3d-crash-fixture".into(),
            logical_commitment_id: "private-witness".into(),
            layout_version: "fragmented-v1".into(),
        },
        q: 2,
        m: 4,
    };
    let token =
        Token::generate_with_material(binding.clone(), &bases, [0x31; 16], [0x42; 32]).unwrap();
    let mut rng = StdRng::seed_from_u64(0x5633_4400);
    let key_provider = || SoftwareTokenStoreKeyProvider::new("software-test-key-v1", [0x55; 32]);

    let mut token_store = TokenStore::open(
        &token_root,
        Box::new(key_provider()),
        Box::new(SoftwareCrashConsistentProvider),
        [0x24; 32],
    )
    .unwrap();
    token_store.insert(&token, &mut rng).unwrap();
    token_store
        .reserve(
            &token.token_id,
            &binding,
            binding.context_digest(),
            "v3d-crash-session",
            "v3d-crash-invocation",
            [0x71; 32],
            &mut rng,
        )
        .unwrap();
    assert_eq!(
        token_store.state(&token.token_id),
        Some(TokenState::Reserved)
    );

    let config = MultiObjectStoreConfig {
        root: spill_root.clone(),
        proof_session: "crashed-proof".into(),
        backend_revision: "libspartan-0.9.0-thinwallet-v3d".into(),
        metadata_key: [0x66; 32],
        maximum_chunk_bytes: 64,
        maximum_temporary_storage_bytes: 1024,
        durability: StateDurability::EphemeralCorrectnessOnly,
    };
    let mut spill = MultiObjectFileBackedStateStore::create(config.clone()).unwrap();
    let descriptor = StateObjectDescriptor::canonical(
        "active-fold",
        &config.proof_session,
        &config.backend_revision,
        "SumcheckFold",
        "Scalar",
        2,
        64,
    );
    spill.create_object(descriptor).unwrap();
    spill.append_chunk("active-fold", 0, &[0x77; 64]).unwrap();
    spill.seal_object("active-fold").unwrap();
    assert_eq!(spill.stats().fsync_calls, 0);
    assert_eq!(spill.stats().skipped_fsync_calls, 1);

    // Model abrupt process loss: neither normal spill cleanup nor token
    // finalization runs. Recovery must burn the already-reserved token.
    std::mem::forget(spill);
    drop(token_store);
    let recovered = TokenStore::open(
        &token_root,
        Box::new(key_provider()),
        Box::new(SoftwareCrashConsistentProvider),
        [0x24; 32],
    )
    .unwrap();
    assert_eq!(recovered.state(&token.token_id), Some(TokenState::Burned));
    assert!(spill_root
        .join("crashed-proof")
        .join("active-fold.state")
        .exists());

    drop(recovered);
    std::fs::remove_dir_all(root).unwrap();
}
