#!/usr/bin/env python3
"""Tests for the privacy-frontier scanner.

Each test corresponds to a claim the paper makes, so a claim cannot drift away
from the tool without a test failing.

    python3 -m unittest -v test_frontier
"""

import json
import os
import unittest

import frontier

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    return frontier.load_schema(os.path.join(HERE, "schemas", name))


def run(name):
    return frontier.analyse(load(name))


class TestSpartan(unittest.TestCase):
    """Section 4.4 / Table 2."""

    @classmethod
    def setUpClass(cls):
        cls.res = run("spartan_hyrax_stock.json")

    def test_split_root_repair_is_derived_not_assumed(self):
        """The tool is given a single tape root and must discover the split."""
        r = self.res["repaired"]
        self.assertIsNotNone(r, "no repair was emitted")
        self.assertEqual(r["root"], "proof")
        self.assertEqual(r["event"], "poly_eval_proof")

    def test_repair_strictly_advances_the_frontier(self):
        r = self.res["repaired"]
        self.assertEqual(r["frontier_was"], 20)
        self.assertEqual(r["frontier_now"], 14)

    def test_frontier_is_at_sat_completion(self):
        f = self.res["frontier"]
        self.assertIsNotNone(f)
        self.assertEqual(f["event"], "poly_eval_proof")

    def test_dpub_suffix_is_the_eval_phase(self):
        suffix = self.res["frontier"]["suffix"]
        for ev in ("derefs_commit", "product_layer_proof", "hash_layer_proof"):
            self.assertIn(ev, suffix)

    def test_every_boundary_object_is_discharged(self):
        f = self.res["frontier"]
        self.assertEqual(sorted(o for o, _ in f["discharged"]),
                         sorted(f["omega"]))
        rules = {r for _, r in f["discharged"]}
        self.assertLessEqual(rules, set(frontier.RULES))

    def test_row_msm_is_admissible_as_dpriv(self):
        """Admissible: the cost stage, not the sweep, rejects delegating it."""
        units = {u["name"]: u for u in self.res["units"]}
        u = units["hyrax_row_msm"]
        self.assertEqual(u["mode"], "DPRIV")
        self.assertEqual(u["certificate"]["scheme"], "PBMO")
        self.assertEqual(u["private_inputs"], ["poly_vars"])

    def test_no_cut_before_sat_opening_is_admissible(self):
        for k in self.res["admissible"]:
            self.assertGreaterEqual(k, 14)

    def test_stock_configuration_has_no_seal(self):
        """`ProverRandomnessPlan::LegacyShared` audits but never seals.

        The stock arm of `seal_sat_frontier` only calls `audit()`, so a stock
        recording carries no seal and the tool has nothing to cross-check
        against -- which is precisely why the repair has to be derived.
        """
        self.assertIsNone(self.res.get("seal_check"))


class TestGroth16(unittest.TestCase):
    """Appendix D: the admissible set is empty."""

    @classmethod
    def setUpClass(cls):
        cls.res = run("groth16.json")

    def test_no_public_suffix_exists(self):
        self.assertIsNone(self.res["frontier"])
        self.assertTrue(self.res["terminal_only"])

    def test_only_the_terminal_cut_is_admissible(self):
        self.assertEqual(self.res["admissible"], [self.res["T"]])

    def test_no_repair_can_help(self):
        """Failures are P1, not P2, so split-root has nothing to fix."""
        self.assertIsNone(self.res["repaired"])
        kinds = {c["kind"] for c in self.res["classes"]}
        self.assertNotIn("P2", kinds)

    def test_dpriv_is_the_only_available_mode(self):
        modes = {u["mode"] for u in self.res["units"]}
        self.assertEqual(modes, {"DPRIV"})
        self.assertEqual(len(self.res["units"]), 5)


class TestRecordedTrace(unittest.TestCase):
    """The JSONL emitted by the instrumentation must agree with the model.

    `recorded_*.jsonl` are produced by `emit/lib_rs_trace_schema.rs` driven over
    the Spartan event sequence; see emit/callsites.md.
    """

    def test_recorded_stock_matches_hand_model(self):
        hand = run("spartan_hyrax_stock.json")
        rec = run("recorded_stock.jsonl")
        self.assertEqual(hand["frontier"]["event"], rec["frontier"]["event"])
        self.assertEqual(hand["repaired"]["root"], rec["repaired"]["root"])
        self.assertEqual([c["kind"] for c in hand["classes"]],
                         [c["kind"] for c in rec["classes"]])

    def test_implemented_split_root_equals_prescribed_repair(self):
        """The deployed root separation is exactly the repair the tool derives.

        Stock records one tape root and must be repaired; ThinWallet records
        two and must not be.  Both must land on the same frontier.
        """
        stock = run("recorded_stock.jsonl")
        tw = run("recorded_thinwallet.jsonl")
        self.assertIsNotNone(stock["repaired"])
        self.assertIsNone(tw["repaired"])
        self.assertEqual(stock["repaired"]["frontier_now"], tw["frontier"]["k"])
        self.assertEqual(stock["frontier"]["suffix"], tw["frontier"]["suffix"])

    def test_split_recording_respects_the_seal(self):
        """The Split arm seals; the derived cut must not lie past it."""
        c = run("recorded_thinwallet.jsonl")["seal_check"]
        self.assertEqual(c["sealed_root"], "sat_proof")
        self.assertTrue(c["agree"],
                        "derived frontier k=%s is past the seal k=%s"
                        % (c["derived_k"], c["seal_k"]))

    def test_recorded_roots_come_from_the_randomness_plan(self):
        """Labels must be the ones `prepare_randomness_plan` actually builds."""
        self.assertEqual(load("recorded_stock.jsonl").roots, ["proof"])
        self.assertEqual(load("recorded_thinwallet.jsonl").roots,
                         ["sat_proof", "eval_proof"])

    def test_out_of_order_trace_is_rejected(self):
        lines = ['{"kind":"root","id":"r","seq":5}',
                 '{"kind":"root","id":"s","seq":1}']
        with self.assertRaises(frontier.SchemaError):
            frontier.schema_from_trace(lines)

    def test_unknown_record_kind_is_rejected(self):
        with self.assertRaises(frontier.SchemaError):
            frontier.schema_from_trace(['{"kind":"mystery","seq":0}'])


class TestProcedureProperties(unittest.TestCase):
    """Appendix C: coverage, monotone sweep, schema well-formedness."""

    def test_classes_partition_the_cut_space(self):
        for name in ("spartan_hyrax_stock.json", "groth16.json"):
            res = run(name)
            covered = []
            for c in res["classes"]:
                covered.extend(range(c["lo"], c["hi"] + 1))
            self.assertEqual(covered, list(range(1, res["T"] + 1)),
                             "coverage failed for %s" % name)

    def test_dependency_set_is_monotone_in_the_sweep(self):
        """Each object enters Dep at most once: this is why the sweep is linear."""
        schema = load("spartan_hyrax_stock.json")
        verdicts = frontier.sweep(schema, frontier.label(schema))
        # verdicts are ordered by k ascending; the sweep runs downwards, so the
        # accumulator at a smaller k must contain the accumulator at a larger k.
        for earlier, later in zip(verdicts[:-1], verdicts[1:]):
            self.assertTrue(later.dep_raw <= earlier.dep_raw)
        self.assertEqual(verdicts[-1].dep_raw, frozenset())

    def test_rejects_non_transcript_consistent_schema(self):
        raw = {"name": "bad", "roots": [], "seeds": {"a": {"sec": "pub"}},
               "events": [{"id": "e1", "in": ["ghost"], "out": ["b"]}]}
        with self.assertRaises(frontier.SchemaError):
            frontier.Schema(raw)

    def test_rejects_undeclared_root(self):
        raw = {"name": "bad", "roots": [], "seeds": {},
               "events": [{"id": "e1", "in": [], "out": ["b"],
                           "draws": "nope"}]}
        with self.assertRaises(frontier.SchemaError):
            frontier.Schema(raw)

    def test_public_coin_annotation_cannot_launder_private_state(self):
        raw = {"name": "bad", "roots": [], "seeds": {"w": {"sec": "priv"}},
               "events": [{"id": "e1", "in": ["w"], "out": ["y"],
                           "sec": "pub"}]}
        with self.assertRaises(frontier.SchemaError):
            frontier.label(frontier.Schema(raw))

    def test_public_coin_annotation_may_read_released_material(self):
        raw = {"name": "ok", "roots": [], "seeds": {"w": {"sec": "priv"}},
               "events": [
                   {"id": "e1", "in": ["w"], "out": ["c"], "release": ["c"]},
                   {"id": "e2", "in": ["c"], "out": ["ch"], "sec": "pub"}]}
        g = frontier.label(frontier.Schema(raw))
        self.assertEqual(g["ch"].sec, "pub")
        self.assertEqual(g["ch"].roots, frozenset())


if __name__ == "__main__":
    unittest.main()
