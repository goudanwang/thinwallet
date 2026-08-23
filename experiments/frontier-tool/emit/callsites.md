# Call sites

Where to place the `record_trace_*` calls of `lib_rs_trace_schema.rs`.

Anchors below were read from the supplied sources: `lib.rs` (instrumentation),
`pbmo_commitment.rs`, `provider.rs`, `random.rs`, `r1csproof.rs`,
`dense_mlpoly.rs`, `sparse_mlpoly.rs`, `phase_v2_pbmo.rs`. One file is still
missing and is listed at the end.

Nothing here has been built against the real workspace. The module itself was
compiled in isolation against stubs of the crate's private helpers
(`enabled`, `path_from_env`, `append_json`, `monotonic_ns`,
`increment_counter`), and the emitted JSONL was fed through `frontier.py`
end to end — see `schemas/recorded_*.jsonl` and `TestRecordedTrace`.

## 1. `thinwallet-instrumentation/src/lib.rs` — verified

One import changes:

```diff
-use std::sync::atomic::{AtomicBool, Ordering};
+use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
```
(line 11.)

Append `lib_rs_trace_schema.rs` at the end of the file. It uses only helpers
that already exist there: `SCHEMA_VERSION` (line 16), `path_from_env`
(line 235), `append_json` (line 241), `increment_counter` (line 695),
`monotonic_ns`. The gating idiom matches
`record_native_row_msm_physical_call` (line 300): every entry point begins with

```rust
let Some(path) = trace_path() else { return };
```

so when `THINWALLET_TRACE_SCHEMA_PATH` is unset the cost is one `getenv` per
call. Events are recorded at phase granularity — 22 calls for a whole proof —
so this cannot perturb a timing run. Still, keep the frozen measurement runs
with the variable unset and record the schema in a separate run, and say so in
the artifact README.

## 2. `pbmo_commitment.rs` — verified

`with_full_pbmo_provider` (line 49) scopes exactly one logical commitment. Put
the run preamble and the delegation-unit declaration there:

```diff
   let output = f();
   let report = ACTIVE_RUN.with(|slot| slot.borrow_mut().take().unwrap().report);
+  #[cfg(feature = "thinwallet-experiment")]
+  if report.selected {
+    thinwallet_instrumentation::record_trace_unit(
+      "hyrax_row_msm", &["commit_inner_row_msm"], "Mask", "PBMO");
+  }
   (output, report)
```

`maybe_commit_private_rows` (line 70) is where the ordered `q`-by-`m` witness
matrix reaches the provider, and it already asserts `scalars.len() == q * m`
and `bases.len() == m`. Record the logical row-MSM event **once here**, after
`finalize`:

```diff
     let points = provider.finalize(session).expect("PBMO finalize failed");
     assert_eq!(points.len(), q);
+    #[cfg(feature = "thinwallet-experiment")]
+    thinwallet_instrumentation::record_trace_event(
+      "commit_inner_row_msm", &["poly_vars", "G"], &["row_points"],
+      None, &[], false);
```

Do **not** put it inside the chunk loop: that loop runs `q * ceil(m/chunk)` =
4,096 times per proof, and the trace schema records one logical event, not one
per physical chunk. The physical/logical distinction is already carried by
`record_native_row_msm_physical_call` and `record_native_row_msm_logical_row`.

The module doc says native row blinding stays in `dense_mlpoly`, so
`native_blinding` — the event that produces the *released* `comm_vars` —
belongs there, not here. See §7.

## 3. `provider.rs` — verified, no new events

The counter block at lines 514–535 already records the physical MSM calls and
the logical rows, gated on `SessionMode::Native`. Leave it alone: the trace
schema needs provenance, not timings, and the delegation unit is the logical
row batch declared in §2.

Two fields worth carrying into the run record so a reviewer can tie a recorded
schema to a specific measured run — `PbmoContext` (line 40) already has them:

```rust
record_trace_certificate("comm_vars", "Hide", &context.logical_commitment_id);
```

`basis_digest` and `relation_shape` serve the same purpose; the analyser
ignores the `ref` string, it is provenance for the reader.

## 4. `lib (1).rs` (libspartan) — verified; the stock/split switch already exists

`prepare_randomness_plan` (line 315) is the configuration switch, and no new
environment variable is needed:

```rust
if std::env::var("THINWALLET_SPARTAN_RANDOMNESS_MODE").as_deref() == Ok("legacy-shared") {
    return ProverRandomnessPlan::LegacyShared(RandomTape::new(b"proof"));
}
...
ProverRandomnessPlan::Split {
    sat_random_tape: RandomTape::from_phase_seed(b"sat_proof", &sat_seed),
    eval_root, circuit_id, invocation_id, transcript_base,
}
```

So the tape labels are `"proof"` for the stock configuration and
`"sat_proof"` / `"eval_proof"` for the split one, and
`THINWALLET_SPARTAN_RANDOMNESS_MODE=legacy-shared` selects the stock recording.
Take the labels from the plan, not from a flag, so the recording cannot
disagree with the configuration that ran:

```diff
   let mut randomness_plan = prepare_randomness_plan(comm, transcript);
+  #[cfg(feature = "thinwallet-experiment")]
+  match &randomness_plan {
+    ProverRandomnessPlan::LegacyShared(_) =>
+      thinwallet_instrumentation::record_trace_preamble_spartan(&["proof"]),
+    ProverRandomnessPlan::Split { .. } =>
+      thinwallet_instrumentation::record_trace_preamble_spartan(
+        &["sat_proof", "eval_proof"]),
+  }
```

`ProverRandomnessPlan::seal_sat_frontier` (line 137) already distinguishes the
two arms: the `Split` arm calls `seal_frontier()`, the `LegacyShared` arm only
calls `audit()`. Record the seal in the `Split` arm only — a stock recording
then carries no seal, which is exactly right, because that is the configuration
in which the repair still has to be derived:

```diff
       Self::Split { sat_random_tape, .. } => {
         sat_random_tape.seal_frontier();
+        #[cfg(feature = "thinwallet-experiment")]
+        thinwallet_instrumentation::record_trace_seal("sat_proof");
         sat_random_tape.audit()
       }
```

`record_sat_randomness_audit` (line 149) already flushes the tape audit
counters next to this; the seal record belongs with them.

Remaining anchors in this file:

| Event | Anchor |
|---|---|
| `assemble_pi_sat`, `fix_d_pub` | around the `r1cs_eval_proof` block, line 1215 |
| Eval phase, stock arm | line 1225, `ProverRandomnessPlan::LegacyShared(mut shared_tape) => R1CSEvalProof::prove(..)` — same shared tape, which is what makes \eqref{eq:p2} fail |
| Eval phase, split arm | line 1240 onward, `execute_local_eval_split`; the Eval tape is built at line 591, `RandomTape::from_phase_seed(b"eval_proof", &eval_seed)` |
| `assemble_proof` | after both arms return |

The two Eval arms are the cleanest possible demonstration of the procedure's
repair: the same delegated suffix, differing only in whether it continues the
Sat tape.

## 5. `random.rs` — verified, and it simplifies the design

Two things in `RandomTape` make the annotation largely mechanical.

**The tape already carries its own root identifier.**
`RandomTape::from_phase_seed(name: &'static [u8], seed: &[u8; 32])` (line 51)
takes the phase label that the production code uses to separate Sat from Eval.
Rather than hand-annotating `draws` at every sampling site, store that label and
expose it:

```diff
 pub struct RandomTape {
   tape: Transcript,
+  root_label: &'static str,
   scalar_samples: u64,
```
```diff
   pub(crate) fn from_phase_seed(name: &'static [u8], seed: &[u8; 32]) -> Self {
     let mut tape = Transcript::new(name);
     tape.append_message(b"phase_seed_v1", seed);
-    Self::from_transcript(tape)
+    let mut this = Self::from_transcript(tape);
+    this.root_label = std::str::from_utf8(name).unwrap_or("unknown_root");
+    this
   }
+
+  pub fn root_label(&self) -> &'static str { self.root_label }
```

Every call site then passes `Some(random_tape.root_label())` instead of a
literal, so the stock/split distinction is whatever the code actually did and
cannot drift from the recording. `RandomTape::new(b"proof")` supplies the stock
label the same way.

**`seal_frontier` is the implementation's own frontier marker.**
`seal_frontier` (line 75) makes `random_scalar` panic on any later sample
(line 57). Record it:

```diff
   pub(crate) fn seal_frontier(&mut self) {
     self.frontier_sealed = true;
+    #[cfg(feature = "thinwallet-experiment")]
+    thinwallet_instrumentation::record_trace_seal(self.root_label);
   }
```

The analyser then checks that the frontier it derives lies at or before the seal
(`TestSpartan::test_derived_frontier_respects_the_implementation_seal`). This
mirrors statically the invariant `random_scalar` enforces at run time, and it is
a stronger check than agreement with a hand model: it ties the derived cut to
the code's own statement of where the Sat phase ends.

## 6. `r1csproof.rs` — verified

`R1CSProof::prove` (line 183) supplies most of the Sat events. Note the real
order differs from a naive reading: the witness polynomial is committed
*before* `z` is assembled.

| Event | Anchor |
|---|---|
| `dense_poly_new` | line 203, `DensePolynomial::new(vars.clone())` |
| `absorb_poly_commitment` (public coin) | line 209, `append_to_transcript(b"poly_commitment")` |
| `assemble_z` | lines 215–226 |
| `challenge_tau` (public coin) | line 229, `challenge_vector(b"challenge_tau")` |
| `multiply_vec` | lines 231–237, `inst.multiply_vec` |
| `prove_phase_one` (`draws`) | lines 239–252, already inside a `PhaseGuard::begin("sumcheck")` |
| `commit_claims_phase1` (`draws`) | lines 262–296, the four `random_scalar(b"*_blind")` calls and the `comm_*_claim` transcript writes |
| `prove_phase_two` (`draws`) | lines 298–345, second `PhaseGuard::begin("sumcheck")` |
| `poly_eval_proof` (`draws`) | lines 355–366, `random_scalar(b"blind_eval")` then `PolyEvalProof::prove`, inside `PhaseGuard::begin("opening")` |

The existing `PhaseGuard` scopes are the natural insertion points: one
`record_trace_event` immediately after each guard's block closes.

## 7. `dense_mlpoly.rs` — verified

| Event | Anchor |
|---|---|
| `sample_poly_blinds` (`draws`) | line 339, `t.random_vector(b"poly_blinds", L_size)` inside `commit` (line 320) |
| `commit_inner_row_msm` | line 202, the `maybe_commit_private_rows` branch — but record it in `pbmo_commitment.rs` per §2, so the local and delegated paths produce the same event |
| `native_blinding` (releases `comm_vars`) | lines 204–210, the `PhaseGuard::begin("native_blinding")` block |

`commit_inner` is defined twice, at line 192 under `#[cfg(feature = "multicore")]`
and at line 257 under `#[cfg(not(...))]`. Both need the `native_blinding` event,
or record it once in `commit` after `commit_inner` returns — simpler, and it
cannot diverge between the two builds.

## 8. `sparse_mlpoly.rs` — verified

`SparseMatPolyEvalProof::prove` (line 2701) is the Eval phase. Its inputs are
`dense` (the public sparse matrices), `rx`, `ry` (released in `pi_sat`), and
`evals` — no witness dependency, which is the property the sweep needs to see.

| Event | Anchor |
|---|---|
| `derefs_commit` | line 2736, `derefs.commit` then `append_to_transcript(b"comm_poly_row_col_ops_val")`; a `record_stage_metrics("eval_commit_nondet", ...)` block already sits here |
| `product_layer_proof` | line 2580, `ProductLayerProof::prove` |
| `hash_layer_proof` (`draws` the Eval root) | line 2593, `HashLayerProof::prove` — the only Eval-phase consumer of `random_tape` |

## 9. `phase_v2_pbmo.rs` — verified

`with_full_pbmo_provider` wraps `patched::SNARK::prove` / `prove_owned` at lines
1279–1298, inside `begin_prover_audit()` (line 1270). Put
`record_trace_preamble_spartan` and the seed declarations just before that
block, and the final flush after the counter block at lines 1312–1350.

Drive the stock/split choice from an environment variable next to the existing
ones:

```rust
let stock = std::env::var("THINWALLET_TRACE_STOCK_ROOTS").as_deref() == Ok("1");
thinwallet_instrumentation::record_trace_preamble_spartan(stock);
```

Record both configurations. The artifact check that matters is
`TestRecordedTrace::test_implemented_split_root_equals_prescribed_repair`: the
stock recording must need a `split-root` repair, the ThinWallet recording must
not, and both must land on the same frontier.

## 10. Auditing the annotations

The `public_coin = true` sites are the ones that need the closest reading:
`absorb_poly_commitment`, `challenge_tau`, `derive_eval_point`. The analyser
clears the tape-root taint on them and refuses the annotation on any event that
reads *unreleased* private state, but it cannot check that a site really is a
deterministic function of the transcript. That judgement is the audit the paper
claims, and the annotation is what makes it inspectable.

Every event in `schemas/spartan_hyrax_stock.json` carries an `_at` field naming
the source line it models, so the hand model and the recording can be diffed
against each other and against the code.
