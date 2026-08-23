use libspartan_patched::multi_state_store::{
    MultiObjectFileBackedStateStore, MultiObjectStoreConfig, ProverStateStore, StateDurability,
};
use libspartan_patched::streaming_sumcheck_fold::{StreamingPolynomial, StreamingScalar as Scalar};
use std::path::PathBuf;

fn store(name: &str) -> MultiObjectFileBackedStateStore {
    let root = std::env::temp_dir().join(format!("thinwallet-v3c-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    MultiObjectFileBackedStateStore::create(MultiObjectStoreConfig {
        root,
        proof_session: format!("session-{name}"),
        backend_revision: "libspartan-0.9.0-thinwallet-v3c".into(),
        metadata_key: [0x3c; 32],
        maximum_chunk_bytes: 64,
        maximum_temporary_storage_bytes: 1024 * 1024,
        durability: StateDurability::SecurityCriticalDurable,
    })
    .unwrap()
}

fn limited_store(
    name: &str,
    maximum_temporary_storage_bytes: u64,
) -> (MultiObjectFileBackedStateStore, PathBuf) {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "thinwallet-v3c-{name}-{}-{nonce}",
        std::process::id()
    ));
    let session = format!("session-{name}");
    let session_root = root.join(&session);
    let store = MultiObjectFileBackedStateStore::create(MultiObjectStoreConfig {
        root,
        proof_session: session,
        backend_revision: "libspartan-0.9.0-thinwallet-v3c".into(),
        metadata_key: [0x3c; 32],
        maximum_chunk_bytes: 64,
        maximum_temporary_storage_bytes,
        durability: StateDurability::SecurityCriticalDurable,
    })
    .unwrap();
    (store, session_root)
}

#[test]
fn adjacent_fold_matches_standard_relation_with_bounded_chunks() {
    let mut store = store("adjacent");
    let values = (0..16).map(Scalar::from).collect::<Vec<_>>();
    let challenge = Scalar::from(7u64);
    let expected = values
        .chunks_exact(2)
        .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
        .collect::<Vec<_>>();
    let mut poly =
        StreamingPolynomial::write(&mut store, "fold-current", "fixture", &values).unwrap();
    let stats = poly
        .fold_adjacent(&mut store, "fold-next", &challenge, 0)
        .unwrap();
    assert_eq!(poly.read_all(&mut store).unwrap(), expected);
    assert!(stats.peak_buffer_bytes <= 256);
    assert!(store.stats().temporary_storage_peak_bytes <= 16 * 32 + 8 * 32);
    store.abort_session_cleanup().unwrap();
}

#[test]
fn top_fold_is_byte_equivalent_to_dense_polynomial_order() {
    let mut store = store("top");
    let values = (0..16).map(Scalar::from).collect::<Vec<_>>();
    let challenge = Scalar::from(11u64);
    let half = values.len() / 2;
    let expected = (0..half)
        .map(|i| values[i] + challenge * (values[i + half] - values[i]))
        .collect::<Vec<_>>();
    let mut poly =
        StreamingPolynomial::write(&mut store, "fold-current", "fixture", &values).unwrap();
    poly.fold_top(&mut store, "fold-next", &challenge, 0)
        .unwrap();
    assert_eq!(poly.read_all(&mut store).unwrap(), expected);
    store.abort_session_cleanup().unwrap();
}

#[test]
fn injected_fold_transition_failure_cleans_session_state() {
    let (mut store, session_root) = limited_store("fold-failure", 640);
    let values = (0..16).map(Scalar::from).collect::<Vec<_>>();
    let mut poly =
        StreamingPolynomial::write(&mut store, "fold-current", "fixture", &values).unwrap();
    let error = poly
        .fold_top(&mut store, "fold-next", &Scalar::from(19u64), 3)
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::OutOfMemory);
    store.abort_session_cleanup().unwrap();
    assert!(!session_root.exists());
}

#[test]
fn fold_state_metadata_binds_round_and_challenge() {
    let (mut store, session_root) = limited_store("challenge-binding", 4096);
    let values = (0..16).map(Scalar::from).collect::<Vec<_>>();
    let challenge = Scalar::from(23u64);
    let mut poly =
        StreamingPolynomial::write(&mut store, "fold-current", "fixture", &values).unwrap();
    poly.fold_top(&mut store, "fold-next", &challenge, 7)
        .unwrap();
    let metadata = std::fs::read(session_root.join("fold-next.meta")).unwrap();
    assert!(metadata
        .windows(b"round-7".len())
        .any(|window| window == b"round-7"));
    let binding = b"challenge-1700000000000000000000000000000000000000000000000000000000000000";
    assert!(metadata
        .windows(binding.len())
        .any(|window| window == binding));
    store.abort_session_cleanup().unwrap();
}
