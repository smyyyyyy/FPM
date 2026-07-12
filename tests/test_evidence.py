from __future__ import annotations

import unittest

from fpm_benchmark.evidence import (
    build_evidence_slots,
    compact_for_llm,
    enrich_core_evidence_slots,
    strip_java_comments,
)


class EvidenceTest(unittest.TestCase):
    def test_source_sink_trace_backfills_user_control_and_path(self) -> None:
        trace = [
            {"role": "SOURCE_CANDIDATE", "semantic_tag": "user_input_candidate"},
            {"role": "SINK_CANDIDATE", "semantic_tag": "response_sink_candidate"},
        ]

        slots = build_evidence_slots("CWE-079", trace)

        self.assertEqual(slots["source_user_controlled"], "yes")
        self.assertEqual(slots["sink_dangerous"], "yes")
        self.assertEqual(slots["path_exists"], "yes")

    def test_enrichment_updates_legacy_slots_and_missing_evidence(self) -> None:
        evidence = {
            "alert_contract": {"cwe": "CWE-022"},
            "annotated_trace": [
                {"role": "SOURCE_CANDIDATE"},
                {"role": "SINK_CANDIDATE"},
            ],
            "evidence_slots": {"source_user_controlled": "unknown"},
            "missing_evidence": ["MISSING_SOURCE_TRUST_LEVEL"],
        }

        enrich_core_evidence_slots(evidence)

        self.assertEqual(evidence["evidence_slots"]["source_user_controlled"], "yes")
        self.assertNotIn("MISSING_SOURCE_TRUST_LEVEL", evidence["missing_evidence"])

    def test_strip_java_comments_preserves_literals_and_lines(self) -> None:
        source = (
            'String url = "https://example.test/a/*b*/"; // label-like comment\n'
            "char slash = '/'; /* block\ncomment */\n"
        )

        cleaned = strip_java_comments(source)

        self.assertIn('"https://example.test/a/*b*/"', cleaned)
        self.assertIn("char slash = '/';", cleaned)
        self.assertNotIn("label-like", cleaned)
        self.assertNotIn("block", cleaned)
        self.assertEqual(cleaned.count("\n"), source.count("\n"))

    def test_source_chain_view_excludes_ground_truth_and_query_results(self) -> None:
        evidence = {
            "alert_id": "a1",
            "alert_contract": {
                "cwe": "CWE-079",
                "primary_location": {"code": "sink(value); // safe"},
            },
            "annotated_trace": [{"code": "source(); /* safe */"}],
            "cwe_profile": {},
            "evidence_slots": {},
            "missing_evidence": [],
            "code_context": {
                "primary_snippet": "sink(value);",
                "related_source_no_comments": "class Example {}",
            },
            "query_history": [{"template_id": "must-not-leak"}],
            "supplemental_evidence": [{"summary": "must-not-leak"}],
            "ground_truth": {"expected_vulnerable": False},
        }

        compact = compact_for_llm(evidence, view="source-chain")

        self.assertNotIn("ground_truth", compact)
        self.assertNotIn("query_history", compact)
        self.assertNotIn("supplemental_evidence", compact)
        self.assertNotIn("evidence_slots", compact)
        self.assertNotIn("missing_evidence", compact)
        self.assertNotIn("safe", compact["alert_contract"]["primary_location"]["code"])
        self.assertNotIn("safe", compact["annotated_trace"][0]["code"])
        self.assertEqual(
            compact["code_context"]["related_source_no_comments"],
            "class Example {}",
        )

    def test_query_centered_view_includes_only_compact_query_evidence(self) -> None:
        evidence = {
            "alert_id": "a1",
            "alert_contract": {"cwe": "CWE-079", "primary_location": {}},
            "annotated_trace": [],
            "cwe_profile": {},
            "code_context": {"related_source_no_comments": "class Example {}"},
            "query_history": [{"template_id": "find-x", "status": "ok"}],
            "supplemental_evidence": [
                {"template_id": "find-x", "status": "ok", "summary": {"tuple_count": 1}}
            ],
            "ground_truth": {"expected_vulnerable": False},
        }

        compact = compact_for_llm(evidence, view="query-centered")

        self.assertNotIn("ground_truth", compact)
        self.assertEqual(compact["query_history"][0]["template_id"], "find-x")
        self.assertEqual(compact["supplemental_evidence"][0]["summary"]["tuple_count"], 1)


if __name__ == "__main__":
    unittest.main()
