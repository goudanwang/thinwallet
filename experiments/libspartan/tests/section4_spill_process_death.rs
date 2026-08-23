use libspartan_patched::multi_state_store::{
    MultiObjectFileBackedStateStore, MultiObjectStoreConfig, ProverStateStore, StateDurability,
    StateObjectDescriptor,
};
use std::fs;
use std::process::Command;

fn config(root: &std::path::Path) -> MultiObjectStoreConfig {
    MultiObjectStoreConfig {
        root: root.to_path_buf(),
        proof_session: "abrupt-session".to_owned(),
        backend_revision: "section4-process-death".to_owned(),
        metadata_key: [0x61; 32],
        maximum_chunk_bytes: 64,
        maximum_temporary_storage_bytes: 1024,
        durability: StateDurability::SecurityCriticalDurable,
    }
}

#[test]
fn abrupt_process_death_is_purged_and_not_resumed() {
    if let Ok(root) = std::env::var("THINWALLET_SECTION4_CRASH_CHILD_ROOT") {
        let config = config(std::path::Path::new(&root));
        let mut store = MultiObjectFileBackedStateStore::create(config.clone()).unwrap();
        store
            .create_object(StateObjectDescriptor::canonical(
                "crash-object",
                &config.proof_session,
                &config.backend_revision,
                "crash-test",
                "Bytes",
                4,
                64,
            ))
            .unwrap();
        store.append_chunk("crash-object", 0, b"data").unwrap();
        std::process::exit(93);
    }

    let root = std::env::temp_dir().join(format!(
        "thinwallet-section4-process-death-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("abrupt_process_death_is_purged_and_not_resumed")
        .arg("--nocapture")
        .env("THINWALLET_SECTION4_CRASH_CHILD_ROOT", &root)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(93));

    let stale = match MultiObjectFileBackedStateStore::create(config(&root)) {
        Ok(_) => panic!("abrupt spill state was resumed"),
        Err(error) => error,
    };
    assert_eq!(stale.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(!root.join("abrupt-session").exists());

    let mut fresh = MultiObjectFileBackedStateStore::create(config(&root)).unwrap();
    assert!(fresh.range_read("crash-object", 0, 1).is_err());
    fresh.abort_session_cleanup().unwrap();
    fs::remove_dir_all(root).unwrap();
}
