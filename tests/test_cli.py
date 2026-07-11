from __future__ import annotations

import unittest

from fpm_benchmark.cli import _controller_next_query, _decision_is_final


class ControllerTest(unittest.TestCase):
    def test_sufficient_tp_or_fp_finishes_without_query(self) -> None:
        for verdict in ("TP", "FP"):
            decision = {"verdict": verdict, "sufficient": True}
            self.assertTrue(_decision_is_final(decision))
            query = _controller_next_query(
                evidence={"alert_contract": {"cwe": "CWE-079"}},
                decision=decision,
                can_continue=True,
            )
            self.assertIsNone(query["template_id"])

    def test_insufficient_tp_uses_requested_query(self) -> None:
        decision = {
            "verdict": "TP",
            "sufficient": False,
            "next_query": {
                "template_id": "find-sink-argument-origin",
                "parameters": {"file": "Example.java", "line": 10},
            },
        }
        query = _controller_next_query(
            evidence={},
            decision=decision,
            can_continue=True,
        )
        self.assertEqual(query["template_id"], "find-sink-argument-origin")

    def test_final_iteration_never_executes_unused_query(self) -> None:
        evidence = {
            "alert_contract": {
                "cwe": "CWE-079",
                "primary_location": {"file": "Example.java", "start_line": 10},
            }
        }
        decision = {
            "verdict": "UNKNOWN",
            "next_query": {
                "template_id": "find-sink-argument-origin",
                "parameters": {"file": "Example.java", "line": 10},
                "reason": "Need origin evidence",
            },
        }

        query = _controller_next_query(
            evidence=evidence,
            decision=decision,
            can_continue=False,
        )

        self.assertIsNone(query["template_id"])


if __name__ == "__main__":
    unittest.main()
