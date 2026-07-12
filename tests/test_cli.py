from __future__ import annotations

import unittest

from fpm_benchmark.cli import (
    _controller_next_query,
    _decision_is_call_failure,
    _decision_is_final,
    _unresolved_decision,
)


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

    def test_gate_blocks_when_checklist_slot_unknown(self) -> None:
        """Even if LLM says sufficient=True, an unfilled checklist slot
        should prevent finalization."""
        cwe = "CWE-327"
        evidence = {
            "alert_contract": {"cwe": cwe},
            "evidence_slots": {
                "api_identified": "yes",
                "argument_extracted": "unknown",
                "argument_is_constant": "unknown",
            },
        }
        decision = {"verdict": "TP", "sufficient": True}
        self.assertFalse(_decision_is_final(decision, evidence))

    def test_gate_passes_when_all_checklist_slots_filled(self) -> None:
        """When all checklist slots are no longer 'unknown', the decision
        should be final even with a strict gate."""
        cwe = "CWE-327"
        evidence = {
            "alert_contract": {"cwe": cwe},
            "evidence_slots": {
                "api_identified": "yes",
                "argument_extracted": "yes",
                "argument_is_constant": "checked_none",
            },
        }
        decision = {"verdict": "FP", "sufficient": True}
        self.assertTrue(_decision_is_final(decision, evidence))

    def test_gate_rejects_failed_evidence_collection(self) -> None:
        evidence = {
            "alert_contract": {"cwe": "CWE-327"},
            "evidence_slots": {
                "api_identified": "yes",
                "argument_extracted": "error",
                "argument_is_constant": "checked_error",
            },
        }
        decision = {"verdict": "TP", "sufficient": True}
        self.assertFalse(_decision_is_final(decision, evidence))

    def test_xss_tp_does_not_require_framework_semantics(self) -> None:
        evidence = {
            "alert_contract": {"cwe": "CWE-079"},
            "evidence_slots": {
                "sink_identified": "yes",
                "source_user_controlled": "yes",
                "sink_dangerous": "yes",
                "path_exists": "yes",
                "sanitizer_present": "checked_none",
                "framework_semantics_known": "unknown",
            },
        }
        decision = {"verdict": "TP", "sufficient": True}
        self.assertTrue(_decision_is_final(decision, evidence))

    def test_xss_fp_requires_refutation_evidence(self) -> None:
        evidence = {
            "alert_contract": {"cwe": "CWE-079"},
            "evidence_slots": {
                "sink_identified": "yes",
                "source_user_controlled": "yes",
                "sink_dangerous": "yes",
                "path_exists": "yes",
                "sanitizer_present": "checked_none",
                "framework_semantics_known": "unknown",
            },
        }
        decision = {"verdict": "FP", "sufficient": True}
        self.assertFalse(_decision_is_final(decision, evidence))
        evidence["query_history"] = [
            {
                "template_id": "find-xss-encoder-nearby",
                "status": "ok",
                "summary": {"tuple_count": 1},
            }
        ]
        self.assertTrue(_decision_is_final(decision, evidence))

    def test_sql_fp_does_not_require_a_confirmed_vulnerable_path(self) -> None:
        evidence = {
            "alert_contract": {"cwe": "CWE-089"},
            "evidence_slots": {
                "sink_identified": "yes",
                "source_user_controlled": "unknown",
                "sink_dangerous": "yes",
                "path_exists": "unknown",
                "safe_api_usage": "unknown",
                "sink_argument_origin": "unknown",
            },
            "query_history": [
                {
                    "template_id": "find-sql-parameterization",
                    "status": "ok",
                    "summary": {"tuple_count": 2},
                }
            ],
        }
        decision = {"verdict": "FP", "sufficient": True}
        self.assertTrue(_decision_is_final(decision, evidence))

    def test_empty_query_is_not_fp_evidence(self) -> None:
        evidence = {
            "alert_contract": {"cwe": "CWE-089"},
            "evidence_slots": {"sink_identified": "yes"},
            "query_history": [
                {
                    "template_id": "find-sql-parameterization",
                    "status": "ok",
                    "summary": {"tuple_count": 0},
                }
            ],
        }
        decision = {"verdict": "FP", "sufficient": True}
        self.assertFalse(_decision_is_final(decision, evidence))

    def test_llm_call_failure_is_detected(self) -> None:
        self.assertTrue(
            _decision_is_call_failure(
                {"verdict": "UNKNOWN", "missing_evidence": ["LLM_CALL_FAILED"]}
            )
        )
        self.assertFalse(_decision_is_call_failure({"verdict": "TP", "missing_evidence": []}))

    def test_unresolved_decision_becomes_unknown_and_keeps_candidate(self) -> None:
        candidate = {
            "verdict": "TP",
            "sufficient": False,
            "missing_evidence": ["MISSING_VALIDATOR_OR_GUARD"],
        }
        final = _unresolved_decision(candidate)
        self.assertEqual(final["verdict"], "UNKNOWN")
        self.assertFalse(final["sufficient"])
        self.assertIs(final["candidate_decision"], candidate)
        self.assertIn("MAX_ITERATIONS_WITHOUT_SUFFICIENT_EVIDENCE", final["missing_evidence"])

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

    def test_gate_triggers_mandatory_query_for_cwe327(self) -> None:
        """CWE-327 with unfilled slots should trigger find-crypto-algorithm."""
        evidence = {
            "alert_contract": {
                "cwe": "CWE-327",
                "primary_location": {"file": "Benchmark.java", "start_line": 84},
            },
            "evidence_slots": {
                "api_identified": "yes",
                "argument_extracted": "unknown",
                "argument_is_constant": "unknown",
            },
        }
        decision = {"verdict": "TP", "sufficient": True,
                    "next_query": {"template_id": None, "parameters": {}}}
        query = _controller_next_query(
            evidence=evidence,
            decision=decision,
            can_continue=True,
        )
        self.assertEqual(query["template_id"], "find-crypto-algorithm")


if __name__ == "__main__":
    unittest.main()
