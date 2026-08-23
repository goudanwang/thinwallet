// ---------------------------------------------------------------------------
// Privacy-frontier trace schema.
//
// Append this section to `thinwallet-instrumentation/src/lib.rs`.  It reuses
// the crate's existing helpers (`enabled`, `path_from_env`, `append_json`,
// `SCHEMA_VERSION`, `monotonic_ns`) and follows the same conventions as
// `record_native_row_msm_physical_call`: gated on the instrumentation profile,
// append-only JSONL, output path taken from an environment variable.
//
// One import line changes at the top of lib.rs:
//
//     -use std::sync::atomic::{AtomicBool, Ordering};
//     +use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
//
// Records identifiers and provenance only.  No witness value, scalar, or point
// ever reaches this path.
// ---------------------------------------------------------------------------

/// Monotone sequence number so a reader can recover event order even if the
/// prover ever records from more than one thread.
static TRACE_SEQ: AtomicU64 = AtomicU64::new(0);

fn trace_path() -> Option<PathBuf> {
    path_from_env("THINWALLET_TRACE_SCHEMA_PATH")
}

fn next_trace_seq() -> u64 {
    TRACE_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Declare a random-tape root identifier.
pub fn record_trace_root(id: &str) {
    let Some(path) = trace_path() else {
        return;
    };
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "root",
            "seq": next_trace_seq(),
            "id": id,
        }),
    );
}

/// Declare an object that has no producing event: the witness, the statement,
/// the public parameters, the commitment basis.
///
/// `sec` must be `"pub"` or `"priv"`.
pub fn record_trace_seed(id: &str, sec: &str) {
    debug_assert!(sec == "pub" || sec == "priv", "bad seed secrecy label");
    let Some(path) = trace_path() else {
        return;
    };
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "seed",
            "seq": next_trace_seq(),
            "id": id,
            "sec": sec,
        }),
    );
}

/// Record one prover event in transcript order.
///
/// * `ins` / `outs` name the objects the event reads and produces.
/// * `draws` names a random-tape root when the event samples prover-private
///   randomness.  Fiat--Shamir challenges are *not* tape draws.
/// * `release` names the outputs written to the transcript, i.e. what enters
///   the boundary record.  Over-declaring here would let private state through
///   the containment test, so this list must match actual transcript writes.
/// * `public_coin` marks a deterministic derivation from transcript-visible
///   material; it clears the tape-root taint.  The analyser rejects the
///   annotation on any event that reads unreleased private state.
pub fn record_trace_event(
    id: &str,
    ins: &[&str],
    outs: &[&str],
    draws: Option<&str>,
    release: &[&str],
    public_coin: bool,
) {
    let Some(path) = trace_path() else {
        return;
    };
    increment_counter("trace_schema_events", 1);
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "event",
            "seq": next_trace_seq(),
            "timestamp_monotonic_ns": monotonic_ns(),
            "id": id,
            "in": ins,
            "out": outs,
            "draws": draws,
            "release": release,
            "public_coin": public_coin,
            "mode": std::env::var("THINWALLET_EXPERIMENT_MODE").ok(),
            "workload": std::env::var("THINWALLET_CREDENTIAL_WORKLOAD").ok(),
        }),
    );
}

/// Declare a candidate delegation unit: a set of events a masking scheme is
/// claimed to cover.  The analyser checks coverage; it does not invent units.
pub fn record_trace_unit(name: &str, events: &[&str], rule: &str, scheme: &str) {
    let Some(path) = trace_path() else {
        return;
    };
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "unit",
            "seq": next_trace_seq(),
            "name": name,
            "events": events,
            "rule": rule,
            "scheme": scheme,
        }),
    );
}

/// Record that a random tape was sealed against further sampling.
///
/// `RandomTape::seal_frontier` is the implementation's own statement of where
/// the Sat phase ends.  Recording it lets the analyser cross-check the frontier
/// it derives against the point the code actually seals, which is a much
/// stronger artifact check than agreement with a hand model.
pub fn record_trace_seal(root: &str) {
    let Some(path) = trace_path() else {
        return;
    };
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "seal",
            "seq": next_trace_seq(),
            "root": root,
        }),
    );
}

/// Declare which certificate rule discharges the exposure of a released object.
pub fn record_trace_certificate(object: &str, rule: &str, reference: &str) {
    let Some(path) = trace_path() else {
        return;
    };
    append_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "certificate",
            "seq": next_trace_seq(),
            "object": object,
            "rule": rule,
            "ref": reference,
        }),
    );
}

/// Record the roots, seeds, and certificates that are fixed for a Spartan run.
///
/// Call once from `SNARK::prove` after `prepare_randomness_plan`, passing the
/// tape labels the plan actually built:
///
/// * `ProverRandomnessPlan::LegacyShared` -> `&["proof"]`
/// * `ProverRandomnessPlan::Split`        -> `&["sat_proof", "eval_proof"]`
///
/// Taking the labels from the plan rather than from a flag means the recording
/// cannot disagree with the configuration that ran.
pub fn record_trace_preamble_spartan(roots: &[&str]) {
    if trace_path().is_none() {
        return;
    }
    for root in roots {
        record_trace_root(root);
    }
    for (id, sec) in [
        ("pp", "pub"),
        ("circ", "pub"),
        ("x", "pub"),
        ("G", "pub"),
        ("H", "pub"),
        ("pubmeta", "pub"),
        ("w", "priv"),
    ] {
        record_trace_seed(id, sec);
    }
    for (object, rule, reference) in [
        ("comm_vars", "Hide", "Hyrax hiding row commitments"),
        ("sc_proof_phase1", "ProofProj", "app:sat-frontier-zk"),
        ("comm_claims1", "Hide", "Pedersen claim commitments"),
        ("sc_proof_phase2", "ProofProj", "app:sat-frontier-zk"),
        ("proof_eval_vars_at_ry", "ProofProj", "app:sat-frontier-zk"),
        ("pi_sat", "ProofProj", "app:sat-frontier-zk"),
        ("d_pub", "PubFun", "public eval claims and replay state"),
        ("comm_derefs", "ProofProj", "public sparse-matrix commitments"),
        ("proof_prod_layer", "ProofProj", "app:sat-frontier-zk"),
        ("proof_hash_layer", "ProofProj", "app:sat-frontier-zk"),
        ("pi_eval", "ProofProj", "app:sat-frontier-zk"),
        ("Pi", "ProofProj", "native Spartan zero knowledge"),
    ] {
        record_trace_certificate(object, rule, reference);
    }
}
