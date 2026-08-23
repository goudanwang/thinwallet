#!/usr/bin/env python3
"""Privacy-frontier scanner.

Implements the procedure of ThinWallet Section 4.3 (Algorithm 1) over a trace
schema emitted by the prover instrumentation.  Standard library only.

    ./frontier.py schemas/spartan_hyrax_stock.json
    ./frontier.py schemas/groth16.json --latex
    ./frontier.py results/runs/<run>/trace_schema.jsonl

Exit status is 0 if a frontier with no open obligation was found, 1 if the
admissible set is empty or every admissible cut has open obligations, and 2 on
a malformed schema.
"""

import argparse
import json
import sys
from collections import OrderedDict

# --------------------------------------------------------------------------
# schema
# --------------------------------------------------------------------------


class SchemaError(Exception):
    pass


class Schema:
    """A trace schema: events in transcript-consistent order over objects."""

    def __init__(self, raw):
        self.name = raw.get("name", "<unnamed>")
        self.leakage = list(raw.get("public_leakage", []))
        self.roots = list(raw.get("roots", []))
        self.seeds = OrderedDict(raw.get("seeds", {}))
        self.events = list(raw.get("events", []))
        self.certificates = OrderedDict(raw.get("certificates", {}))
        self.units = list(raw.get("delegation_units", []))
        # Optional: the event after which the implementation sealed its tape.
        self.sealed_after = raw.get("sealed_after")
        self.sealed_root = raw.get("sealed_root")
        self._validate()

    def _validate(self):
        seen = set(self.seeds)
        ids = set()
        for k, ev in enumerate(self.events):
            for field in ("id", "in", "out"):
                if field not in ev:
                    raise SchemaError("event %d missing field %r" % (k, field))
            if ev["id"] in ids:
                raise SchemaError("duplicate event id %r" % ev["id"])
            ids.add(ev["id"])
            for o in ev["in"]:
                if o not in seen:
                    raise SchemaError(
                        "event %r reads %r before it is produced; the schema is "
                        "not transcript-consistent" % (ev["id"], o))
            draws = ev.get("draws")
            if draws is not None and draws not in self.roots:
                raise SchemaError(
                    "event %r draws from undeclared root %r" % (ev["id"], draws))
            for o in ev["out"]:
                seen.add(o)
        for u in self.units:
            for e in u.get("events", []):
                if e not in ids:
                    raise SchemaError("delegation unit names unknown event %r" % e)

    @property
    def T(self):
        return len(self.events)


def schema_from_trace(lines):
    """Assemble a Schema from the JSONL stream emitted by the prover.

    The Rust side is append-only and records no global state, so ordering comes
    from the append order; `seq` is carried only so a reader can detect
    interleaving if the prover ever records from more than one thread.
    """
    recs = []
    for i, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            recs.append(json.loads(line))
        except ValueError as e:
            raise SchemaError("trace line %d is not JSON: %s" % (i, e))

    seqs = [r["seq"] for r in recs if "seq" in r]
    if seqs != sorted(seqs):
        raise SchemaError("trace records are out of sequence; the prover "
                          "recorded from more than one thread")

    raw = {"name": None, "roots": [], "seeds": {}, "events": [],
           "certificates": {}, "delegation_units": [], "public_leakage": []}
    for r in recs:
        kind = r.get("kind")
        if kind == "root":
            raw["roots"].append(r["id"])
        elif kind == "seed":
            raw["seeds"][r["id"]] = {"sec": r["sec"]}
        elif kind == "event":
            ev = {"id": r["id"], "in": r["in"], "out": r["out"]}
            if r.get("draws"):
                ev["draws"] = r["draws"]
            if r.get("release"):
                ev["release"] = r["release"]
            if r.get("public_coin"):
                ev["sec"] = "pub"
            raw["events"].append(ev)
            if raw["name"] is None and r.get("mode"):
                raw["name"] = "recorded run (%s/%s)" % (
                    r.get("mode"), r.get("workload"))
        elif kind == "certificate":
            raw["certificates"][r["object"]] = {"rule": r["rule"],
                                                "ref": r.get("ref", "")}
        elif kind == "seal":
            if not raw["events"]:
                raise SchemaError("tape sealed before any event was recorded")
            raw["sealed_after"] = raw["events"][-1]["id"]
            raw["sealed_root"] = r["root"]
        elif kind == "unit":
            raw["delegation_units"].append({
                "name": r["name"], "events": r["events"],
                "certificate": {"rule": r["rule"], "scheme": r["scheme"]}})
        else:
            raise SchemaError("unknown trace record kind %r" % kind)
    raw["name"] = raw["name"] or "recorded run"
    return Schema(raw)


def load_schema(path):
    """Accept either a hand-written schema object or a recorded JSONL trace."""
    with open(path) as fh:
        head = fh.read(1)
        fh.seek(0)
        if head == "{" and not path.endswith(".jsonl"):
            return Schema(json.load(fh))
        return schema_from_trace(fh)


# --------------------------------------------------------------------------
# phase 1 -- provenance labelling
# --------------------------------------------------------------------------


class Label:
    __slots__ = ("sec", "roots", "born", "released")

    def __init__(self, sec, roots, born, released):
        self.sec = sec          # "pub" | "priv"
        self.roots = roots      # frozenset of tape-root identifiers
        self.born = born        # event index (1-based); 0 for seeds
        self.released = released

    def __repr__(self):
        return "Label(%s, %s, born=%d, rel=%s)" % (
            self.sec, sorted(self.roots), self.born, self.released)


def label(schema):
    """One forward pass.  Returns {object: Label}."""
    g = OrderedDict()
    for name, spec in schema.seeds.items():
        sec = spec.get("sec", "pub")
        if sec not in ("pub", "priv"):
            raise SchemaError("seed %r has bad sec %r" % (name, sec))
        g[name] = Label(sec, frozenset(spec.get("roots", [])), 0,
                        bool(spec.get("release", False)))

    for k, ev in enumerate(schema.events, start=1):
        inputs = [g[o] for o in ev["in"]]
        sec = "priv" if any(l.sec == "priv" for l in inputs) else "pub"
        roots = frozenset().union(*[l.roots for l in inputs]) if inputs \
            else frozenset()
        if ev.get("draws"):
            roots = roots | {ev["draws"]}
            # randomness makes an output private unless the schema says the
            # draw is public coin (Fiat-Shamir challenges are not tape draws).
            sec = "priv"
        forced = ev.get("sec")
        if forced == "priv":
            sec = "priv"
        elif forced == "pub":
            # An explicit public-coin derivation: the output is a deterministic
            # function of transcript-visible material, so it carries no secret
            # tape provenance.  Clearing the root taint here is what keeps
            # Fiat-Shamir challenges from spuriously propagating a root across
            # the cut.  This annotation is auditable: it must not be attached to
            # an event that reads unreleased private state.
            sec, roots = "pub", frozenset()
            bad = [o for o in ev["in"]
                   if g[o].sec == "priv" and not g[o].released]
            if bad:
                raise SchemaError(
                    "event %r is annotated public-coin but reads unreleased "
                    "private %s"
                    % (ev["id"], bad))
        released = set(ev.get("release", []))
        for o in ev["out"]:
            g[o] = Label(sec, roots, k, o in released)
    return g


# --------------------------------------------------------------------------
# phase 2 -- monotone suffix sweep
# --------------------------------------------------------------------------


class Verdict:
    __slots__ = ("k", "kind", "witness", "omega", "dep", "dep_raw")

    def __init__(self, k, kind, witness, omega, dep, dep_raw):
        self.k = k
        self.kind = kind            # "P1" | "P2" | "candidate"
        self.witness = witness      # first obstructing object or root
        self.omega = omega          # frozenset: released objects born <= k
        self.dep = dep              # frozenset: suffix inputs from outside
        self.dep_raw = dep_raw      # frozenset: monotone accumulator

    @property
    def admissible(self):
        return self.kind == "candidate"


def sweep(schema, g):
    """One backward pass.  Returns [Verdict] indexed by cut k = 1..T.

    P1 (containment): every private object the suffix still reads must already
    lie inside the released boundary record Omega_k.  The equality form
    Dep>k n Priv<=k = {} is too strong: pi_sat is itself witness-derived and is
    released on purpose, so it must be permitted through Omega_k and then
    discharged by an exposure certificate.

    P2 (root separation): no random-tape root drawn by the suffix may also have
    been drawn by a private object of the prefix.  Roots inherited by material
    inside Omega_k do not count: that material is released deliberately and is
    covered by the exposure certificate discharging Omega_k.
    """
    dep = set()
    produced_after = set()
    suffix_draws = set()
    verdicts = [None] * (schema.T + 1)

    for k in range(schema.T, 0, -1):
        ev = schema.events[k - 1]
        # events k+1..T form the suffix; entering iteration k, fold in e_k's
        # own reads only once we move the cut below k.
        if k < schema.T:
            nxt = schema.events[k]
            produced_after |= set(nxt["out"])
            dep |= set(nxt["in"])
            if nxt.get("draws"):
                suffix_draws.add(nxt["draws"])
        dep_ext = {o for o in dep if o not in produced_after}

        omega = frozenset(o for o, l in g.items()
                          if l.released and l.born <= k)
        priv_before = {o for o in g
                       if g[o].sec == "priv" and g[o].born <= k}

        leak = sorted(o for o in dep_ext
                      if o in priv_before and o not in omega)
        if leak:
            verdicts[k] = Verdict(k, "P1", leak[0], omega, frozenset(dep_ext),
                                  frozenset(dep))
            continue

        # P2 concerns fresh suffix draws, not roots inherited by material that
        # is released on purpose: a root inside Omega_k is already covered by
        # the exposure certificate discharging Omega_k.  Objects the suffix
        # reads from outside Omega_k are public by the P1 test above, but may
        # still carry a root, so their roots are included.
        suffix_roots = set(suffix_draws)
        for o in dep_ext:
            if o not in omega:
                suffix_roots |= g[o].roots
        prefix_roots = set()
        for o in priv_before:
            prefix_roots |= g[o].roots
        cross = sorted(suffix_roots & prefix_roots)
        if cross:
            verdicts[k] = Verdict(k, "P2", cross[0], omega, frozenset(dep_ext),
                                  frozenset(dep))
            continue

        verdicts[k] = Verdict(k, "candidate", None, omega, frozenset(dep_ext),
                                  frozenset(dep))
    return verdicts[1:]


# --------------------------------------------------------------------------
# phase 3 -- obligation discharge
# --------------------------------------------------------------------------

RULES = ("PubFun", "ProofProj", "Fresh", "Mask", "Hide")


def discharge(omega, schema, g):
    """Split Omega into (discharged, open).  Public objects are immediate."""
    done, open_ = [], []
    for o in sorted(omega):
        if g[o].sec == "pub":
            done.append((o, "PubFun"))
            continue
        cert = schema.certificates.get(o)
        if cert and cert.get("rule") in RULES:
            done.append((o, cert["rule"]))
        else:
            open_.append(o)
    return done, open_


# --------------------------------------------------------------------------
# phase 4 -- split-root repair
# --------------------------------------------------------------------------


def repair(schema, k, root):
    """Return a schema in which events after k draw from a fresh root."""
    raw = {
        "name": schema.name + "+split(%s@%d)" % (root, k),
        "public_leakage": schema.leakage,
        "roots": schema.roots + [root + "_suffix"],
        "seeds": schema.seeds,
        "certificates": schema.certificates,
        "delegation_units": schema.units,
        "sealed_after": schema.sealed_after,
        "sealed_root": schema.sealed_root,
        "events": [],
    }
    for i, ev in enumerate(schema.events, start=1):
        ev = dict(ev)
        if i > k and ev.get("draws") == root:
            ev["draws"] = root + "_suffix"
        raw["events"].append(ev)
    return Schema(raw)


# --------------------------------------------------------------------------
# phase 5 -- declared delegation units
# --------------------------------------------------------------------------


def check_units(schema, g):
    """A masking scheme is an invention, not something a sweep can discover.

    The schema therefore *declares* candidate delegation units, and the tool
    only checks that a certificate covers each unit's exposed inputs and that
    its outputs are recovered by the client.
    """
    out = []
    idx = {ev["id"]: i for i, ev in enumerate(schema.events, start=1)}
    for u in schema.units:
        evs = u.get("events", [])
        span = sorted(idx[e] for e in evs)
        inner = set()
        for e in evs:
            inner |= set(schema.events[idx[e] - 1]["out"])
        exposed = set()
        for e in evs:
            exposed |= {o for o in schema.events[idx[e] - 1]["in"]
                        if o not in inner}
        priv_exposed = sorted(o for o in exposed if g[o].sec == "priv")
        cert = u.get("certificate")
        ok = bool(cert) and cert.get("rule") == "Mask"
        out.append({
            "name": u.get("name", ",".join(evs)),
            "span": (span[0], span[-1]) if span else None,
            "private_inputs": priv_exposed,
            "mode": "DPRIV" if ok else "OPEN",
            "certificate": cert,
            "note": u.get("note", ""),
        })
    return out


# --------------------------------------------------------------------------
# classes
# --------------------------------------------------------------------------


def classes(schema, verdicts):
    """Maximal runs of a constant verdict; a partition of [1, T] by Thm C.4."""
    runs = []
    for v in verdicts:
        key = (v.kind, v.witness)
        if runs and runs[-1]["key"] == key:
            runs[-1]["hi"] = v.k
        else:
            runs.append({"key": key, "lo": v.k, "hi": v.k})
    for r in runs:
        r["kind"], r["witness"] = r.pop("key")
        r["events"] = (schema.events[r["lo"] - 1]["id"],
                       schema.events[r["hi"] - 1]["id"])
    return runs


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------


def analyse(schema, allow_repair=True):
    g = label(schema)
    verdicts = sweep(schema, g)
    result = {
        "schema": schema.name,
        "T": schema.T,
        "repaired": None,
        "classes": classes(schema, verdicts),
        "units": check_units(schema, g),
    }

    def earliest(vs, kind):
        for v in vs:
            if v.kind == kind:
                return v
        return None

    # Phase 4.  The frontier is the *earliest* admissible cut, so a cut that
    # passes P1 and fails only P2 is worth repairing exactly when it lies
    # strictly earlier than the earliest cut that is already admissible.
    p2 = earliest(verdicts, "P2")
    adm = earliest(verdicts, "candidate")
    if allow_repair and p2 is not None and (adm is None or p2.k < adm.k):
        s2 = repair(schema, p2.k, p2.witness)
        g2 = label(s2)
        v2 = sweep(s2, g2)
        adm2 = earliest(v2, "candidate")
        if adm2 is not None and (adm is None or adm2.k < adm.k):
            result["repaired"] = {
                "at": p2.k, "root": p2.witness,
                "event": s2.events[p2.k - 1]["id"],
                "frontier_was": adm.k if adm else None,
                "frontier_now": adm2.k,
            }
            schema, g, verdicts = s2, g2, v2
            result["classes"] = classes(schema, verdicts)
            result["units"] = check_units(schema, g)
    admissible = [v for v in verdicts if v.admissible]

    frontier = None
    trace = []
    for v in admissible:
        done, open_ = discharge(v.omega, schema, g)
        trace.append({"k": v.k, "event": schema.events[v.k - 1]["id"],
                      "discharged": done, "open": open_})
        if not open_ and v.k < schema.T:
            frontier = {"k": v.k, "event": schema.events[v.k - 1]["id"],
                        "omega": sorted(v.omega), "discharged": done,
                        "suffix": [e["id"] for e in schema.events[v.k:]]}
            break
    result["admissible"] = [v.k for v in admissible]
    result["obligations"] = trace
    result["frontier"] = frontier
    result["terminal_only"] = bool(admissible) and \
        all(v.k == schema.T for v in admissible)

    # Cross-check against the implementation's own seal point, when recorded.
    #
    # The derived frontier may legitimately lie *before* the seal: sealing later
    # is conservative, and the events in between are pure assembly of material
    # already released.  What must not happen is the reverse -- the code drawing
    # from the sealed root after the cut the procedure derives.  That is the
    # same invariant `RandomTape::random_scalar` enforces at run time when the
    # tape is sealed, so this check mirrors it statically.
    if schema.sealed_after is not None:
        ids = [e["id"] for e in schema.events]
        seal_k = ids.index(schema.sealed_after) + 1
        got_k = frontier["k"] if frontier else None
        result["seal_check"] = {
            "sealed_after": schema.sealed_after,
            "sealed_root": schema.sealed_root,
            "seal_k": seal_k,
            "derived_frontier": frontier["event"] if frontier else None,
            "derived_k": got_k,
            "agree": got_k is not None and got_k <= seal_k,
        }
    return result


def render(res):
    L = []
    a = L.append
    a("schema      : %s" % res["schema"])
    a("events      : %d" % res["T"])
    if res["repaired"]:
        r = res["repaired"]
        a("repair      : split-root %r at k=%d (%s)"
          % (r["root"], r["at"], r["event"]))
        a("              earliest admissible cut %s -> %d"
          % (r["frontier_was"] if r["frontier_was"] else "none", r["frontier_now"]))
    a("")
    a("computed cut classes (a partition of [1, T])")
    a("-" * 78)
    a("%-9s %-11s %-34s %s" % ("cut range", "verdict", "obstruction", "events"))
    a("-" * 78)
    for c in res["classes"]:
        rng = "%d-%d" % (c["lo"], c["hi"]) if c["lo"] != c["hi"] else str(c["lo"])
        w = c["witness"] or "--"
        kind = {"P1": "P1 fails", "P2": "P2 fails",
                "candidate": "admissible"}[c["kind"]]
        a("%-9s %-11s %-34s %s..%s" % (rng, kind, w, c["events"][0],
                                       c["events"][1]))
    a("")
    if res["frontier"]:
        f = res["frontier"]
        a("frontier    : k=%d after %s" % (f["k"], f["event"]))
        a("Omega_k     : %s" % ", ".join(f["omega"]))
        a("discharged  : %s" % ", ".join("%s/%s" % (o, r)
                                         for o, r in f["discharged"]))
        a("DPUB suffix : %s" % ", ".join(f["suffix"]))
    elif res["terminal_only"]:
        a("frontier    : NONE -- the admissible set contains only the terminal")
        a("              cut, whose suffix is empty.  No DPUB segment exists at")
        a("              any granularity (Thm C.5 makes refinement no help).")
    else:
        a("frontier    : NONE -- admissible set is empty")
    if res["obligations"] and not res["frontier"]:
        for t in res["obligations"]:
            if t["open"]:
                a("open at k=%d (%s): %s" % (t["k"], t["event"],
                                             ", ".join(t["open"])))
    if res.get("seal_check"):
        c = res["seal_check"]
        a("seal check  : code seals %r after %s (k=%d); derived frontier k=%s"
          % (c["sealed_root"], c["sealed_after"], c["seal_k"],
             c["derived_k"] if c["derived_k"] else "none"))
        a("              %s" % (
            "OK: no private draw from the sealed root after the derived cut"
            if c["agree"] else
            "VIOLATION: the code samples past the derived frontier"))
        a("")
    a("declared delegation units")
    a("-" * 78)
    if not res["units"]:
        a("(none)")
    for u in res["units"]:
        a("%-22s span %-9s mode %-6s private inputs: %s"
          % (u["name"],
             "%d-%d" % u["span"] if u["span"] else "--",
             u["mode"],
             ", ".join(u["private_inputs"]) or "--"))
        if u["note"]:
            a("%-22s %s" % ("", u["note"]))
    return "\n".join(L)


LATEX_ROW = ("    %s & %s & %s \\\\")


def render_latex(res):
    """Emit the body of the computed cut-class table so the paper cannot drift."""
    kindtex = {
        "P1": r"\eqref{eq:p1} fails: suffix still reads \texttt{%s}",
        "P2": r"\eqref{eq:p2} fails: root \texttt{%s} crosses",
        "candidate": r"\eqref{eq:p1}--\eqref{eq:p2} hold",
    }
    L = ["% generated by frontier.py -- do not edit by hand",
         "%% schema: %s" % res["schema"]]
    if res["repaired"]:
        r = res["repaired"]
        L.append("%% split-root repair on %s at k=%d (%s); earliest admissible "
                 "cut %s -> %d"
                 % (r["root"], r["at"], r["event"],
                    r["frontier_was"] if r["frontier_was"] else "none",
                    r["frontier_now"]))
    for c in res["classes"]:
        rng = "%d--%d" % (c["lo"], c["hi"]) if c["lo"] != c["hi"] else str(c["lo"])
        body = kindtex[c["kind"]]
        body = body % c["witness"].replace("_", r"\_") if c["witness"] else body
        L.append(LATEX_ROW % (
            r"\texttt{%s}" % c["events"][0].replace("_", r"\_"),
            body,
            rng))
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("schema")
    ap.add_argument("--latex", action="store_true",
                    help="emit LaTeX rows for the computed cut-class table")
    ap.add_argument("--json", action="store_true", help="emit raw result JSON")
    ap.add_argument("--no-repair", action="store_true",
                    help="report the schema as recorded, without applying the "
                         "split-root repair")
    args = ap.parse_args(argv)

    try:
        schema = load_schema(args.schema)
    except SchemaError as e:
        print("schema error: %s" % e, file=sys.stderr)
        return 2

    res = analyse(schema, allow_repair=not args.no_repair)
    if args.json:
        print(json.dumps(res, indent=2, default=sorted))
    elif args.latex:
        print(render_latex(res))
    else:
        print(render(res))
    return 0 if res["frontier"] else 1


if __name__ == "__main__":
    sys.exit(main())
