# frontier-tool

Reference implementation of the privacy-frontier procedure (ThinWallet §4.3,
Algorithm 1). Python 3, standard library only, no build step — an artifact
reviewer can run it directly.

```
$ python3 frontier.py schemas/spartan_hyrax_stock.json
$ python3 frontier.py schemas/groth16.json
$ python3 frontier.py schemas/spartan_hyrax_stock.json --latex   # paper table rows
$ python3 frontier.py schemas/groth16.json --json                # machine-readable
$ python3 scripts/generate_table1.py                              # Table 1 rows
$ python3 -m unittest discover -v                                 # 29 tests
```

Exit status: `0` frontier found and fully discharged, `1` no usable frontier,
`2` malformed schema.

## What it does

Consumes a **trace schema** — a prover presented as a transcript-consistent
event sequence over labelled objects — and computes, for *every* cut index,
whether the suffix may be delegated. It then discharges the exposure
obligations of the earliest admissible cut against a fixed rule library,
reports whatever it cannot discharge, and lists the declared delegation units
it can admit in masked form.

## Sweep semantics

The implementation deliberately distinguishes the monotone accumulator from
the external dependency set used at each cut:

```text
dep_raw(k) = union of all inputs read by suffix events
produced_after(k) = union of all outputs produced by suffix events
Dep(k) = dep_raw(k) - produced_after(k)
```

`dep_raw` is union-only. There is no live-in killing pass. Suffix-internal
objects are removed from `Dep(k)` by the `produced_after` filter, so an object
created and consumed entirely after the cut does not pollute the frontier.
Birth indices are then used independently to define the prefix sets:

```text
Priv(k) = {o | sec(o) = private and born(o) <= k}
Omega(k) = {o | released(o) and born(o) <= k}
viol_1(k) = (Dep(k) intersect Priv(k)) - Omega(k)
```

The root-crossing check is `viol_2(k)`: roots freshly drawn in the suffix, plus
roots carried by external dependencies outside `Omega(k)`, are intersected
with roots carried by prefix-private objects. The first object or root in the
corresponding nonempty set is stored as the verdict witness.

The point is that the paper's cut-class table is **output**, not input. Running
the tool on a schema that declares one shared tape root, the Spartan frontier
and the root-separation repair are both derived:

```
repair      : split-root 'proof' at k=14 (poly_eval_proof)
              earliest admissible cut 20 -> 14
frontier    : k=14 after poly_eval_proof
DPUB suffix : assemble_pi_sat, fix_d_pub, derive_eval_point, derefs_commit,
              product_layer_proof, hash_layer_proof, assemble_pi_eval,
              assemble_proof
seal check  : code seals 'sat_proof' after assemble_pi_sat (k=15);
              derived frontier k=14
              OK: no private draw from the sealed root after the derived cut
```

Event ids are the implementation's, not the paper's prose: each event in
`schemas/spartan_hyrax_stock.json` carries an `_at` field naming the source
line it models, so a reviewer can diff the model against the code.

and on Groth16 the admissible set collapses:

```
frontier    : NONE -- the admissible set contains only the terminal
              cut, whose suffix is empty.
```

## Schema format

```jsonc
{
  "name": "...",
  "public_leakage": ["x", "dims", ...],   // documentation only
  "roots": ["proof"],                     // declared random-tape roots

  "seeds": {                              // objects with no producing event
    "w": {"sec": "priv"},
    "x": {"sec": "pub"}
  },

  "events": [                             // transcript-consistent order
    {
      "id":      "row_msm",
      "in":      ["z", "G"],
      "out":     ["C_raw"],
      "draws":   "proof",                 // optional: samples from this root
      "release": ["C_raw"],               // optional: outputs put on the wire
      "sec":     "pub"                    // optional: public-coin derivation
    }
  ],

  "certificates": {                       // discharges exposure obligations
    "pi_sat": {"rule": "ProofProj", "ref": "app:sat-frontier-zk"}
  },

  "delegation_units": [                   // candidate DPRIV segments
    {"name": "hyrax_row_msm", "events": ["row_msm"],
     "certificate": {"rule": "Mask", "scheme": "PBMO"}}
  ]
}
```

### The two annotations that require auditing

Everything else is mechanical; these two are judgements and an artifact
reviewer should check them against the source.

**`release`** — the outputs an event puts on the wire, i.e. what enters
`Omega_k`. Marking an object released asserts that the native protocol already
publishes it. Over-marking would let private state through P1, so this list must
correspond to actual transcript writes.

**`sealed_after` / `record_trace_seal`** — where `RandomTape::seal_frontier`
was called. The analyser checks the frontier it derives lies at or before that
point; the reverse would mean the prover samples prefix-private randomness
inside the delegated suffix. This mirrors statically what `random_scalar`
enforces at run time on a sealed tape.

**`sec: "pub"`** — a public-coin derivation: the output is a deterministic
function of transcript-visible material, so it carries no secret tape
provenance and its root taint is cleared. Without this, Fiat–Shamir challenges
would propagate a tape root across every cut and no frontier would ever be
found. The tool refuses the annotation on any event that reads *unreleased*
private state, so it cannot be used to launder a witness dependency
(`test_public_coin_annotation_cannot_launder_private_state`).

## Two corrections the implementation forced

Both were found by making the conditions executable; both are now reflected in
the paper.

**P1 must be containment, not disjointness.** The natural reading
`Dep>k ∩ Priv≤k = ∅` is unsatisfiable for any real prover: `pi_sat` is itself
witness-derived and is published on purpose, so the Eval suffix necessarily
reads private-labelled material. The implementable condition is

```
Dep>k ∩ Priv≤k  ⊆  Omega_k
```

— everything private the suffix still reads must already lie inside the
released boundary record — with simulatability of `Omega_k` then discharged by
P3. Nothing is weakened: a cut whose `Omega_k` cannot be discharged is still
rejected, and the trivial cut at k=0 fails P3.

**P2 concerns fresh suffix draws, not inherited roots.** Taking the roots of
the whole of `Dep>k` over-rejects: `pi_sat`'s blinds legitimately carry the Sat
root, and that exposure is covered by the certificate discharging `Omega_k`.
The condition is that no root *drawn* by the suffix was also drawn by
prefix-private state; roots inherited by material inside `Omega_k` do not
count.

## Certificate rules

| Rule | Applies when |
|---|---|
| `PubFun` | deterministic function of the public leakage (applied automatically to `pub` objects) |
| `ProofProj` | a projection of the native proof, native scheme is zero knowledge |
| `Fresh` | drawn independently of all private state given the public leakage |
| `Mask` | output of a masking scheme with proven input privacy |
| `Hide` | hiding commitment to private data |

An object in `Omega_k` with no rule is reported `open`. The tool never assumes
an obligation away.

## What the tool does not do

- It does not invent masking schemes. Candidate `DPRIV` segments are
  **declared** in the schema and the tool only checks that a certificate covers
  their exposed private inputs. Discovering that a segment *could* be masked is
  a design act, not a graph query.
- It does not prove the certificates. `ProofProj` and `Mask` are discharged by
  the paper's appendices; the tool records which rule was claimed for which
  object so that the two cannot silently diverge.
- It does not decide profitability. Admissibility is the privacy axis only; the
  cost stage is measurement (§8), and the row-MSM boundary is the case where
  the two axes disagree.

## Files

```
frontier.py                        the procedure
schemas/spartan_hyrax_stock.json   hand model: Spartan/Hyrax, ONE tape root
schemas/groth16.json               hand model: Groth16, AHKM's target setting
schemas/recorded_stock.jsonl       emitted by the instrumentation, stock roots
schemas/recorded_thinwallet.jsonl  emitted by the instrumentation, split roots
test_frontier.py                   24 tests, one per paper claim
tests/test_toy_frontier.py         5 minimal dependency/cut regression tests
scripts/generate_table1.py         explicit Table 1 generation entry point
emit/lib_rs_trace_schema.rs        recorder to append to the instrumentation crate
emit/callsites.md                  where to place the recorder calls
EMITTER.md                         rationale and artifact checks
```

`frontier.py` accepts either form: a hand-written schema object, or the JSONL
the instrumentation appends during a run.

`schemas/spartan_hyrax_stock.json` declares the *stock* single tape root
(`RandomTape::new(b"proof")`, the `ProverRandomnessPlan::LegacyShared` arm)
rather than ThinWallet's separated `sat_proof` / `eval_proof` roots, so the
split-root repair has to be derived rather than assumed. The configuration is
selected by the existing `THINWALLET_SPARTAN_RANDOMNESS_MODE=legacy-shared`;
no new switch was added.

The two `recorded_*.jsonl` fixtures were produced by the Rust recorder in
`emit/`, driven over the Spartan event sequence. The check that matters is
`test_implemented_split_root_equals_prescribed_repair`: the stock recording
needs a `split-root` repair, the ThinWallet recording does not, and both land
on the same frontier — so the deployed root separation is exactly the repair
the procedure prescribes.

## Real ThinWallet recording

The checked-in `schemas/recorded_stock.jsonl` and
`schemas/recorded_thinwallet.jsonl` are no longer the archive-supplied driver
fixtures. They were regenerated by two actual `phase_v2_pbmo semi 12` prover
executions on a Samsung SM-S9110 running Android 16. The stock run selected
`THINWALLET_SPARTAN_RANDOMNESS_MODE=legacy-shared`; the split run used the
default independent Sat/Eval roots. Both runs completed proof generation and
the unchanged upstream verifier accepted both proofs.

The exact device, build, binary and trace hashes, prover results, and the
failed Android malicious-spool attempt are recorded in
`results/android-real-recording/recording_manifest.json`. These traces are
audit artifacts, not timing measurements.
