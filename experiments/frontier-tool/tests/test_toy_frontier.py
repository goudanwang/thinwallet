#!/usr/bin/env python3
"""Small cut-level tests for the privacy-frontier sweep."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import frontier  # noqa: E402


def schema(*, seeds, events, roots=None, certificates=None):
    return frontier.Schema({
        "name": "toy",
        "roots": roots or [],
        "seeds": seeds,
        "events": events,
        "certificates": certificates or {},
    })


def verdict_at(s, k):
    verdicts = frontier.sweep(s, frontier.label(s))
    return verdicts[k - 1]


class TestToyFrontiers(unittest.TestCase):
    def test_private_chain_cut_after_each_event(self):
        s = schema(
            seeds={"w": {"sec": "priv"}},
            events=[
                {"id": "e1", "in": ["w"], "out": ["y"]},
                {"id": "e2", "in": ["y"], "out": ["o"]},
            ],
        )

        after_e1 = verdict_at(s, 1)
        after_e2 = verdict_at(s, 2)
        self.assertEqual((after_e1.kind, after_e1.witness), ("P1", "y"))
        self.assertEqual(after_e1.dep, frozenset({"y"}))
        self.assertEqual(after_e2.kind, "candidate")
        self.assertEqual(after_e2.dep, frozenset())

    def test_suffix_internal_object_does_not_enter_external_frontier(self):
        s = schema(
            seeds={"public": {"sec": "pub"}},
            events=[
                {"id": "e1", "in": ["public"], "out": ["p"]},
                {"id": "e2", "in": ["p"], "out": ["y"]},
                {"id": "e3", "in": ["y"], "out": ["o"]},
            ],
        )

        after_e1 = verdict_at(s, 1)
        self.assertEqual(after_e1.kind, "candidate")
        self.assertEqual(after_e1.dep, frozenset({"p"}))
        self.assertNotIn("y", after_e1.dep)
        self.assertIn("y", after_e1.dep_raw)

    def test_released_private_object_satisfies_containment(self):
        s = schema(
            seeds={"w": {"sec": "priv"}},
            events=[
                {"id": "sat", "in": ["w"], "out": ["pi_sat"],
                 "release": ["pi_sat"]},
                {"id": "eval", "in": ["pi_sat"], "out": ["omega"]},
            ],
            certificates={"pi_sat": {"rule": "ProofProj"}},
        )

        labels = frontier.label(s)
        after_sat = frontier.sweep(s, labels)[0]
        priv_before = {o for o, value in labels.items()
                       if value.sec == "priv" and value.born <= 1}
        self.assertLessEqual(after_sat.dep & priv_before, after_sat.omega)
        self.assertEqual(after_sat.kind, "candidate")
        self.assertEqual(frontier.analyse(s)["frontier"]["event"], "sat")

    def test_random_root_crossing_is_repaired_by_split(self):
        s = schema(
            roots=["proof"],
            seeds={"w": {"sec": "priv"}},
            events=[
                {"id": "sat", "in": ["w"], "out": ["pi_sat"],
                 "draws": "proof", "release": ["pi_sat"]},
                {"id": "eval", "in": ["pi_sat"], "out": ["o"],
                 "draws": "proof"},
            ],
            certificates={"pi_sat": {"rule": "ProofProj"}},
        )

        self.assertEqual((verdict_at(s, 1).kind, verdict_at(s, 1).witness),
                         ("P2", "proof"))
        result = frontier.analyse(s)
        self.assertEqual(result["repaired"]["root"], "proof")
        self.assertEqual(result["repaired"]["at"], 1)
        self.assertEqual(result["frontier"]["event"], "sat")

    def test_dead_private_object_does_not_cause_false_violation(self):
        s = schema(
            seeds={"w": {"sec": "priv"}, "public": {"sec": "pub"}},
            events=[
                {"id": "e1", "in": ["w"], "out": ["x"]},
                {"id": "e2", "in": ["public"], "out": ["o"]},
            ],
        )

        after_e1 = verdict_at(s, 1)
        self.assertEqual(after_e1.kind, "candidate")
        self.assertEqual(after_e1.dep, frozenset({"public"}))
        self.assertNotIn("x", after_e1.dep)


if __name__ == "__main__":
    unittest.main()
