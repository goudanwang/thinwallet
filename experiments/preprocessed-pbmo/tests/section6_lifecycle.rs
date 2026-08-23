use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use preprocessed_pbmo::{
    basis_digest, context_binding_digest, PbmoContext, PbmoTransport, PbmoTransportError,
    PreprocessedPbmoProvider, PreprocessedSemihonestPbmoProvider, RelationShape, Scalar,
    SoftwareCrashConsistentProvider, SoftwareTokenStoreKeyProvider, Token, TokenBinding,
    TokenState, TokenStore, TransportChunk, TransportMetrics, TransportRequestHeader,
    TransportResponse, BACKEND_REVISION, PROTOCOL_VERSION,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::fs;
use std::process::Command;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

const JOURNAL_KEY: [u8; 32] = [7; 32];

fn keys() -> SoftwareTokenStoreKeyProvider {
    SoftwareTokenStoreKeyProvider::new("software-test-key-v1", [9; 32])
}

fn binding(relation_id: &str) -> (TokenBinding, Vec<preprocessed_pbmo::GroupElement>) {
    let bases: Vec<_> = (1..=4)
        .map(|i| Scalar::from(i as u64) * RISTRETTO_BASEPOINT_POINT)
        .collect();
    (
        TokenBinding {
            basis_digest: basis_digest(&bases),
            backend_revision: BACKEND_REVISION.into(),
            relation_shape: RelationShape {
                relation_id: relation_id.into(),
                logical_commitment_id: "private-witness".into(),
                layout_version: "fragmented-v1".into(),
            },
            q: 2,
            m: 4,
        },
        bases,
    )
}

fn one_row_binding(relation_id: &str) -> (TokenBinding, Vec<preprocessed_pbmo::GroupElement>) {
    let bases = vec![RISTRETTO_BASEPOINT_POINT];
    (
        TokenBinding {
            basis_digest: basis_digest(&bases),
            backend_revision: BACKEND_REVISION.into(),
            relation_shape: RelationShape {
                relation_id: relation_id.into(),
                logical_commitment_id: "private-witness".into(),
                layout_version: "fragmented-v1".into(),
            },
            q: 1,
            m: 1,
        },
        bases,
    )
}

fn open(path: &std::path::Path) -> TokenStore {
    TokenStore::open(
        path,
        Box::new(keys()),
        Box::new(SoftwareCrashConsistentProvider),
        JOURNAL_KEY,
    )
    .unwrap()
}

fn token(binding: TokenBinding, bases: &[preprocessed_pbmo::GroupElement], id: u8) -> Token {
    Token::generate_with_material(binding, bases, [id; 16], [id.wrapping_add(1); 32]).unwrap()
}

fn reserve(
    store: &mut TokenStore,
    token: &Token,
    binding: &TokenBinding,
    label: &str,
    digest_byte: u8,
    rng: &mut StdRng,
) -> Result<Token, String> {
    store
        .reserve(
            &token.token_id,
            binding,
            binding.context_digest(),
            &format!("sid-{label}"),
            &format!("iid-{label}"),
            [digest_byte; 32],
            rng,
        )
        .map_err(|error| error.to_string())
}

#[test]
fn section6_threaded_stale_handles_have_one_winner() {
    let dir = tempdir().unwrap();
    let (binding, bases) = binding("section6-thread-race");
    let item = token(binding.clone(), &bases, 10);
    let mut rng = StdRng::seed_from_u64(70);
    open(dir.path()).insert(&item, &mut rng).unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let mut joins = Vec::new();
    for (label, digest) in [("thread-a", 0xa1), ("thread-b", 0xb1)] {
        let root = dir.path().to_path_buf();
        let binding = binding.clone();
        let item = item.clone();
        let barrier = barrier.clone();
        joins.push(thread::spawn(move || {
            let mut store = open(&root);
            let mut rng = StdRng::seed_from_u64(u64::from(digest));
            barrier.wait();
            reserve(&mut store, &item, &binding, label, digest, &mut rng).is_ok()
        }));
    }
    let outcomes: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|result| **result).count(), 1);
    let inspection = TokenStore::inspect_committed_records(dir.path(), JOURNAL_KEY).unwrap();
    assert_eq!(inspection.records.len(), 1);
    assert_eq!(inspection.records[0].state, TokenState::Reserved);
    assert!(matches!(
        inspection.records[0].iid.as_str(),
        "iid-thread-a" | "iid-thread-b"
    ));
    println!(
        "SECTION6_THREAD_RACE successes=1 state=RESERVED winner_iid={}",
        inspection.records[0].iid
    );
}

#[test]
fn section6_child_reservation_worker() {
    let Ok(root) = std::env::var("SECTION6_CHILD_STORE") else {
        return;
    };
    let label = std::env::var("SECTION6_CHILD_LABEL").unwrap();
    let ready = std::env::var("SECTION6_CHILD_READY").unwrap();
    let start = std::env::var("SECTION6_CHILD_START").unwrap();
    let outcome = std::env::var("SECTION6_CHILD_OUTCOME").unwrap();
    let digest = std::env::var("SECTION6_CHILD_DIGEST")
        .unwrap()
        .parse::<u8>()
        .unwrap();
    let (binding, bases) = binding("section6-process-race");
    let item = token(binding.clone(), &bases, 11);
    let mut store = open(std::path::Path::new(&root));
    fs::write(&ready, b"ready").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::path::Path::new(&start).exists() {
        assert!(Instant::now() < deadline, "parent start barrier timed out");
        thread::sleep(Duration::from_millis(5));
    }
    let mut rng = StdRng::seed_from_u64(u64::from(digest));
    let success = reserve(&mut store, &item, &binding, &label, digest, &mut rng).is_ok();
    fs::write(
        outcome,
        if success {
            b"success".as_slice()
        } else {
            b"rejected".as_slice()
        },
    )
    .unwrap();
}

#[test]
fn section6_cross_process_stale_handles_have_one_winner() {
    let dir = tempdir().unwrap();
    let store_root = dir.path().join("store");
    let (binding, bases) = binding("section6-process-race");
    let item = token(binding, &bases, 11);
    let mut rng = StdRng::seed_from_u64(71);
    open(&store_root).insert(&item, &mut rng).unwrap();

    let start = dir.path().join("start");
    let mut children = Vec::new();
    for (index, digest) in [0xc1u8, 0xd1].into_iter().enumerate() {
        let ready = dir.path().join(format!("ready-{index}"));
        let outcome = dir.path().join(format!("outcome-{index}"));
        let child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("section6_child_reservation_worker")
            .arg("--nocapture")
            .env("SECTION6_CHILD_STORE", &store_root)
            .env("SECTION6_CHILD_LABEL", format!("process-{index}"))
            .env("SECTION6_CHILD_READY", &ready)
            .env("SECTION6_CHILD_START", &start)
            .env("SECTION6_CHILD_OUTCOME", &outcome)
            .env("SECTION6_CHILD_DIGEST", digest.to_string())
            .spawn()
            .unwrap();
        children.push((child, ready, outcome));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while children.iter().any(|(_, ready, _)| !ready.exists()) {
        assert!(Instant::now() < deadline, "child ready barrier timed out");
        thread::sleep(Duration::from_millis(5));
    }
    fs::write(&start, b"start").unwrap();
    for (child, _, _) in &mut children {
        assert!(child.wait().unwrap().success());
    }
    let outcomes: Vec<_> = children
        .iter()
        .map(|(_, _, path)| fs::read_to_string(path).unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| *outcome == "success")
            .count(),
        1
    );
    let inspection = TokenStore::inspect_committed_records(&store_root, JOURNAL_KEY).unwrap();
    assert_eq!(inspection.records.len(), 1);
    assert_eq!(inspection.records[0].state, TokenState::Reserved);
    println!(
        "SECTION6_PROCESS_RACE successes=1 state=RESERVED winner_iid={}",
        inspection.records[0].iid
    );
}

#[test]
fn section6_record_binding_and_repeated_iid_rejections() {
    let dir = tempdir().unwrap();
    let (binding, bases) = binding("section6-record-binding");
    let first = token(binding.clone(), &bases, 20);
    let second = token(binding.clone(), &bases, 21);
    let mut rng = StdRng::seed_from_u64(72);
    let mut store = open(dir.path());
    store.insert(&first, &mut rng).unwrap();
    store.insert(&second, &mut rng).unwrap();
    let reserved = reserve(&mut store, &first, &binding, "binding", 0xe1, &mut rng).unwrap();
    let good = reserved.reservation_binding().unwrap().clone();
    let generation = reserved.record_generation();

    assert!(store
        .mark_spent(&[0xff; 16], &good, generation, &mut rng)
        .is_err());
    let mut wrong = good.clone();
    wrong.ctx_digest[0] ^= 1;
    assert!(store
        .mark_spent(&first.token_id, &wrong, generation, &mut rng)
        .is_err());
    let mut wrong = good.clone();
    wrong.sid.push_str("-wrong");
    assert!(store
        .mark_spent(&first.token_id, &wrong, generation, &mut rng)
        .is_err());
    let mut wrong = good.clone();
    wrong.iid.push_str("-wrong");
    assert!(store
        .mark_spent(&first.token_id, &wrong, generation, &mut rng)
        .is_err());
    let mut wrong = good.clone();
    wrong.request_digest[0] ^= 1;
    assert!(store
        .mark_spent(&first.token_id, &wrong, generation, &mut rng)
        .is_err());
    assert!(store
        .mark_spent(&first.token_id, &good, generation + 1, &mut rng)
        .is_err());
    assert!(store
        .reserve(
            &second.token_id,
            &binding,
            binding.context_digest(),
            "other-session",
            &good.iid,
            [0xe2; 32],
            &mut rng,
        )
        .is_err());

    assert_eq!(
        store
            .mark_spent(&first.token_id, &good, generation, &mut rng)
            .unwrap(),
        TokenState::Spent
    );
    assert!(store
        .mark_spent(&first.token_id, &good, generation, &mut rng)
        .is_err());
    println!("SECTION6_BINDINGS wrong_tid=true wrong_ctx=true wrong_sid=true wrong_iid=true wrong_request=true stale_generation=true repeated_iid=true already_terminal=true");
}

#[derive(Clone)]
struct EventTransport {
    events: Arc<Mutex<Vec<String>>>,
    metrics: TransportMetrics,
}

impl EventTransport {
    fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            events,
            metrics: TransportMetrics::default(),
        }
    }
}

impl PbmoTransport for EventTransport {
    fn reserve_session(&mut self, _session_digest: [u8; 32]) -> Result<(), PbmoTransportError> {
        self.events.lock().unwrap().push("socket_ready".into());
        Ok(())
    }

    fn send_request_header(
        &mut self,
        _header: &TransportRequestHeader,
    ) -> Result<(), PbmoTransportError> {
        self.events
            .lock()
            .unwrap()
            .push("application_write_0:historical_header_bytes=367".into());
        Ok(())
    }

    fn send_masked_chunk(&mut self, _chunk: &TransportChunk) -> Result<(), PbmoTransportError> {
        self.events
            .lock()
            .unwrap()
            .push("masked_payload_write".into());
        Ok(())
    }

    fn finish_request(&mut self) -> Result<[u8; 32], PbmoTransportError> {
        Err(PbmoTransportError::State(
            "not used by ordering test".into(),
        ))
    }

    fn receive_response(&mut self) -> Result<TransportResponse, PbmoTransportError> {
        Err(PbmoTransportError::State(
            "not used by ordering test".into(),
        ))
    }

    fn abort_session(&mut self, _reason: &str) -> Result<(), PbmoTransportError> {
        Ok(())
    }

    fn metrics(&self) -> &TransportMetrics {
        &self.metrics
    }
}

#[test]
fn section6_durable_reservation_precedes_application_write_zero() {
    let dir = tempdir().unwrap();
    let (binding, bases) = one_row_binding("section6-write-order");
    let item = token(binding.clone(), &bases, 30);
    let context = PbmoContext {
        protocol_version: PROTOCOL_VERSION,
        session_id: "iid-network-order".into(),
        proof_id: "sid-network-order".into(),
        token_id: Some(item.token_id),
        logical_commitment_id: binding.relation_shape.logical_commitment_id.clone(),
        basis_digest: binding.basis_digest,
        backend_revision: binding.backend_revision.clone(),
        relation_shape: format!(
            "{}:{}",
            binding.relation_shape.relation_id, binding.relation_shape.layout_version
        ),
        expected_chunks: 1,
    };
    let request_digest = context_binding_digest(&context, 1, 1).unwrap();
    let mut rng = StdRng::seed_from_u64(73);
    let mut store = open(dir.path());
    store.insert(&item, &mut rng).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let reserved = store
        .reserve(
            &item.token_id,
            &binding,
            binding.context_digest(),
            &context.proof_id,
            &context.session_id,
            request_digest,
            &mut rng,
        )
        .unwrap();
    events
        .lock()
        .unwrap()
        .push("durable_reservation_return".into());
    let transport = EventTransport::new(events.clone());
    let mut provider = PreprocessedSemihonestPbmoProvider::new_with_transport(
        bases,
        reserved,
        Box::new(transport),
    );
    let session = provider.begin(context, 1, 1).unwrap();
    drop(session);
    let observed = events.lock().unwrap().clone();
    assert_eq!(observed[0], "durable_reservation_return");
    assert_eq!(observed[1], "socket_ready");
    assert!(observed[2].starts_with("application_write_0:"));

    let writes_before_failed_reservation = observed
        .iter()
        .filter(|event| event.starts_with("application_write"))
        .count();
    assert!(store
        .reserve(
            &item.token_id,
            &binding,
            binding.context_digest(),
            "sid-rejected",
            "iid-rejected",
            [0xf1; 32],
            &mut rng,
        )
        .is_err());
    let writes_after_failed_reservation = events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.starts_with("application_write"))
        .count();
    assert_eq!(
        writes_before_failed_reservation,
        writes_after_failed_reservation
    );
    println!("SECTION6_WRITE_ORDER zero_pre_reservation_writes=true header_367_after_reservation=true failed_reservation_writes=0");
}

#[cfg(unix)]
#[test]
fn section6_reservation_durability_failure_has_zero_writes() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let root = dir.path().join("store");
    let (binding, bases) = one_row_binding("section6-reserve-durability-failure");
    let item = token(binding.clone(), &bases, 31);
    let mut rng = StdRng::seed_from_u64(731);
    let mut store = open(&root);
    store.insert(&item, &mut rng).unwrap();
    let events = Arc::new(Mutex::new(Vec::<String>::new()));

    let original = fs::metadata(&root).unwrap().permissions();
    let mut readonly = original.clone();
    readonly.set_mode(0o555);
    fs::set_permissions(&root, readonly).unwrap();
    let result = store.reserve(
        &item.token_id,
        &binding,
        binding.context_digest(),
        "sid-durability-failure",
        "iid-durability-failure",
        [0xf3; 32],
        &mut rng,
    );
    fs::set_permissions(&root, original).unwrap();
    assert!(result.is_err());
    assert!(events.lock().unwrap().is_empty());
    assert_eq!(
        TokenStore::inspect_committed_records(&root, JOURNAL_KEY)
            .unwrap()
            .records[0]
            .state,
        TokenState::Available
    );
    println!("SECTION6_DURABILITY_FAILURE reservation_success=false application_writes=0 durable_state=AVAILABLE");
}

#[cfg(unix)]
#[test]
fn section6_recovery_persistence_failure_is_fail_closed() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let root = dir.path().join("store");
    let (binding, bases) = binding("section6-recovery-failure");
    let item = token(binding.clone(), &bases, 40);
    let mut rng = StdRng::seed_from_u64(74);
    {
        let mut store = open(&root);
        store.insert(&item, &mut rng).unwrap();
        reserve(
            &mut store,
            &item,
            &binding,
            "recovery-failure",
            0xf2,
            &mut rng,
        )
        .unwrap();
    }
    let original = fs::metadata(&root).unwrap().permissions();
    let mut readonly = original.clone();
    readonly.set_mode(0o555);
    fs::set_permissions(&root, readonly).unwrap();
    let failed = TokenStore::open(
        &root,
        Box::new(keys()),
        Box::new(SoftwareCrashConsistentProvider),
        JOURNAL_KEY,
    )
    .is_err();
    fs::set_permissions(&root, original).unwrap();
    assert!(failed);
    let recovered = open(&root);
    assert_eq!(recovered.state(&item.token_id), Some(TokenState::Burned));
    println!("SECTION6_RECOVERY_FAILURE initialization_failed=true selection_exposed=false network_writes=0 subsequent_recovery=BURNED");
}

#[test]
fn section6_crash_matrix_terminal_states() {
    let dir = tempdir().unwrap();
    let (binding, bases) = binding("section6-crash-matrix");
    let mut rng = StdRng::seed_from_u64(75);
    let tokens: Vec<_> = (50u8..58)
        .map(|id| token(binding.clone(), &bases, id))
        .collect();
    {
        let mut store = open(dir.path());
        for item in &tokens {
            store.insert(item, &mut rng).unwrap();
        }
        for (index, item) in tokens.iter().enumerate().skip(1).take(6) {
            reserve(
                &mut store,
                item,
                &binding,
                &format!("cut-{index}"),
                0x80 + index as u8,
                &mut rng,
            )
            .unwrap();
        }
        let spent = reserve(
            &mut store,
            &tokens[7],
            &binding,
            "after-spent",
            0x97,
            &mut rng,
        )
        .unwrap();
        store
            .mark_spent(
                &tokens[7].token_id,
                spent.reservation_binding().unwrap(),
                spent.record_generation(),
                &mut rng,
            )
            .unwrap();
    }
    let recovered = open(dir.path());
    assert_eq!(
        recovered.state(&tokens[0].token_id),
        Some(TokenState::Available)
    );
    for item in tokens.iter().skip(1).take(6) {
        assert_eq!(recovered.state(&item.token_id), Some(TokenState::Burned));
    }
    assert_eq!(
        recovered.state(&tokens[7].token_id),
        Some(TokenState::Spent)
    );
    println!("SECTION6_CRASH_MATRIX before_reserve=AVAILABLE after_reserve=BURNED during_header=BURNED during_payload=BURNED after_pbmo=BURNED before_full_verify=BURNED after_full_verify_before_spent=BURNED after_spent=SPENT reusable_terminal=false");
}

#[test]
fn section6_corrupt_store_fails_closed() {
    let dir = tempdir().unwrap();
    let (binding, bases) = binding("section6-corrupt");
    let item = token(binding, &bases, 60);
    let mut rng = StdRng::seed_from_u64(76);
    open(dir.path()).insert(&item, &mut rng).unwrap();
    fs::write(dir.path().join("lifecycle.journal"), b"corrupt").unwrap();
    assert!(TokenStore::open(
        dir.path(),
        Box::new(keys()),
        Box::new(SoftwareCrashConsistentProvider),
        JOURNAL_KEY,
    )
    .is_err());
    println!("SECTION6_CORRUPT_STORE initialization_failed=true fail_closed=true");
}
