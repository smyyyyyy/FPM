from __future__ import annotations

import unittest
from unittest.mock import patch

from fpm_benchmark.cli import (
    _build_llm_client,
    _controller_next_query,
    _decision_is_call_failure,
    _decision_is_final,
    _gate_observation,
    _normalize_query_request,
    _update_slots_from_query,
    _unresolved_decision,
)


class ControllerTest(unittest.TestCase):
    def test_query_location_parameters_are_controller_owned(self) -> None:
        evidence = {
            "alert_contract": {
                "cwe": "CWE-078",
                "primary_location": {"file": "real/Case.java", "start_line": 42},
            },
            "annotated_trace": [],
        }
        manifest = {
            "templates": [
                {
                    "id": "find-command-execution-arguments",
                    "enabled": True,
                    "parameters": ["file", "line"],
                }
            ]
        }

        normalized = _normalize_query_request(
            {
                "template_id": "find-command-execution-arguments",
                "parameters": {"file": "redacted/Case.java", "line": 1},
            },
            evidence,
            manifest,
        )

        self.assertEqual(normalized["parameters"], {"file": "real/Case.java", "line": 42})

    def test_client_uses_configured_api_key_environment(self) -> None:
        with patch.dict(
            "os.environ",
            {"DEEPSEEK_API_KEY": "go-key", "DEEPSEEK_OFFICIAL_API_KEY": "official-key"},
        ):
            client = _build_llm_client(
                {
                    "api_key_env": "DEEPSEEK_OFFICIAL_API_KEY",
                    "base_url": "https://api.deepseek.com",
                    "model": "deepseek-v4-flash",
                }
            )

        self.assertEqual(client.api_key, "official-key")
        self.assertEqual(client.base_url, "https://api.deepseek.com")

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
                "known_weak_api_or_algorithm": "no",
                "known_strong_algorithm": "yes",
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

    def test_xss_fp_requires_path_relevant_refutation_evidence(self) -> None:
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
        self.assertFalse(_decision_is_final(decision, evidence))
        evidence["evidence_slots"]["sanitizer_present"] = "yes"
        self.assertTrue(_decision_is_final(decision, evidence))

    def test_nearby_query_does_not_claim_path_sanitization(self) -> None:
        evidence = {"evidence_slots": {"sanitizer_present": "unknown"}}
        _update_slots_from_query(
            evidence,
            {
                "status": "ok",
                "template_id": "find-xss-encoder-nearby",
                "summary": {"tuple_count": 1},
            },
        )
        self.assertEqual(evidence["evidence_slots"]["sanitizer_present"], "unknown")
        self.assertEqual(evidence["evidence_slots"]["nearby_sanitizer_found"], "yes")

    def test_constant_query_does_not_claim_validator_or_sanitizer(self) -> None:
        evidence = {
            "evidence_slots": {
                "sanitizer_present": "unknown",
                "validator_present": "unknown",
            }
        }
        _update_slots_from_query(
            evidence,
            {
                "status": "ok",
                "template_id": "find-constant-assignment-nearby",
                "summary": {"tuple_count": 2},
            },
        )
        self.assertEqual(evidence["evidence_slots"]["sanitizer_present"], "unknown")
        self.assertEqual(evidence["evidence_slots"]["validator_present"], "unknown")

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
                    "summary": {
                        "tuple_count": 2,
                        "facts": [
                            {"message": "SQL evidence: method=setString, arg=value"}
                        ],
                    },
                }
            ],
        }
        _update_slots_from_query(evidence, evidence["query_history"][0])
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

    def test_weak_crypto_evidence_rejects_contradictory_fp(self) -> None:
        evidence = {
            "alert_contract": {"cwe": "CWE-327"},
            "annotated_trace": [
                {"code": 'String algorithm = props.getProperty("alg", "DESede/ECB/PKCS5Padding");'}
            ],
            "evidence_slots": {
                "api_identified": "yes",
                "argument_extracted": "unknown",
                "known_weak_api_or_algorithm": "unknown",
                "known_strong_algorithm": "unknown",
            },
        }
        result = {
            "status": "ok",
            "template_id": "find-crypto-algorithm",
            "summary": {
                "tuple_count": 1,
                "facts": [{"message": "crypto algorithm argument: algorithm"}],
            },
        }
        _update_slots_from_query(evidence, result)
        self.assertEqual(evidence["evidence_slots"]["known_weak_api_or_algorithm"], "yes")
        self.assertTrue(
            _decision_is_final(
                {"verdict": "TP", "sufficient": True, "confidence": "high"}, evidence
            )
        )
        self.assertFalse(
            _decision_is_final(
                {"verdict": "FP", "sufficient": True, "confidence": "high"}, evidence
            )
        )

    def test_trust_boundary_transfer_is_not_fp_evidence(self) -> None:
        evidence = {
            "alert_contract": {"cwe": "CWE-501"},
            "evidence_slots": {
                "source_identified": "yes",
                "source_user_controlled": "yes",
                "trust_boundary_crossing": "yes",
                "validator_present": "unknown",
            },
            "query_history": [
                {
                    "template_id": "find-trust-boundary-transfer",
                    "status": "ok",
                    "summary": {"tuple_count": 1},
                }
            ],
        }
        self.assertFalse(
            _decision_is_final(
                {"verdict": "FP", "sufficient": True, "confidence": "high"}, evidence
            )
        )
        self.assertTrue(
            _decision_is_final(
                {"verdict": "TP", "sufficient": True, "confidence": "high"}, evidence
            )
        )

    def test_session_origin_query_can_support_high_confidence_fp(self) -> None:
        evidence = {
            "alert_contract": {"cwe": "CWE-501"},
            "annotated_trace": [
                {"role": "SOURCE_CANDIDATE"},
                {"role": "SINK_CANDIDATE"},
            ],
            "evidence_slots": {
                "source_identified": "yes",
                "source_user_controlled": "yes",
                "trust_boundary_crossing": "yes",
                "validator_present": "unknown",
            },
            "query_history": [
                {
                    "template_id": "find-session-attribute-origin",
                    "status": "ok",
                    "summary": {"tuple_count": 3},
                }
            ],
        }
        self.assertTrue(
            _decision_is_final(
                {"verdict": "FP", "sufficient": True, "confidence": "high"}, evidence
            )
        )
        self.assertFalse(
            _decision_is_final(
                {"verdict": "FP", "sufficient": True, "confidence": "medium"}, evidence
            )
        )

    def test_gate_observation_uses_controller_finality(self) -> None:
        evidence = {
            "alert_contract": {"cwe": "CWE-327"},
            "evidence_slots": {
                "api_identified": "yes",
                "argument_extracted": "yes",
                "known_weak_api_or_algorithm": "yes",
            },
            "query_history": [{"template_id": "find-crypto-algorithm", "status": "ok"}],
        }
        observation = _gate_observation(
            {"verdict": "TP", "sufficient": True, "confidence": "high"}, evidence
        )
        self.assertEqual(
            observation,
            {
                "semantic_consistent": True,
                "checklist_satisfied": True,
                "controller_final": True,
                "query_count_before_decision": 1,
            },
        )


if __name__ == "__main__":
    unittest.main()
