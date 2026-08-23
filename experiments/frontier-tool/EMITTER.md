# Artifact checks and build hygiene

`emit/callsites.md` says where each `record_trace_*` call goes. This file says
what the recordings are *for* and how to keep them from perturbing the numbers.

## Status

The recorder module compiles (checked in isolation against stubs of the
instrumentation crate's private helpers) and its output has been driven end to
end through `frontier.py` — `schemas/recorded_*.jsonl` are real emitter output,
not hand-written fixtures. What has **not** happened is a build against the real
workspace: the call sites in `emit/callsites.md` are placed from reading the
sources, not from compiling them.

## The three checks that matter

**1. The recording agrees with the model.**
`TestRecordedTrace::test_recorded_stock_matches_hand_model` — the frontier and
the class verdicts derived from the recording must equal those derived from
`schemas/spartan_hyrax_stock.json`. If they diverge, either the model is wrong
or the annotations are.

**2. The deployed root separation is the prescribed repair.**
`TestRecordedTrace::test_implemented_split_root_equals_prescribed_repair` —
record both arms of `ProverRandomnessPlan`. The `LegacyShared` recording must
need a `split-root` repair; the `Split` recording must not; both must land on
the same frontier. This says ThinWallet's phase separation is exactly the fix
the procedure derives from the stock prover, rather than a coincidence.

**3. The derived cut respects the implementation's own seal.**
`TestRecordedTrace::test_split_recording_respects_the_seal` —
`ProverRandomnessPlan::seal_sat_frontier` calls `RandomTape::seal_frontier`,
which makes any later sample from the Sat tape panic. The derived frontier must
lie at or before that point. Sealing later than the derived cut is conservative
and fine; drawing past it would mean the prover samples prefix-private
randomness inside the delegated suffix.

Note that the stock arm only calls `audit()` and never seals, so a stock
recording carries no seal — correctly, since that is the configuration whose
repair is still to be derived.

## Build hygiene

Keep `THINWALLET_TRACE_SCHEMA_PATH` **unset** for every run whose timings appear
in the paper, and record the schema in a separate run with the same inputs.

The cost when unset is one `getenv` per call and there are 22 calls per proof,
so the overhead is not measurable — but the artifact README should still state
which runs were recorded and which were timed, because a reviewer will ask.

## Reproducing

```
THINWALLET_SPARTAN_RANDOMNESS_MODE=legacy-shared \
THINWALLET_TRACE_SCHEMA_PATH=out/recorded_stock.jsonl \
  <prover invocation>

THINWALLET_TRACE_SCHEMA_PATH=out/recorded_thinwallet.jsonl \
  <prover invocation>

python3 frontier.py out/recorded_stock.jsonl
python3 frontier.py out/recorded_thinwallet.jsonl
python3 -m unittest test_frontier
```
