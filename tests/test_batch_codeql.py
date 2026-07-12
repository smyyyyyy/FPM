from __future__ import annotations

import unittest

from fpm_benchmark.batch_codeql import query_cache_key, render_batched_template
from fpm_benchmark.query_templates import find_template, load_template_manifest


class BatchCodeQLTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_template_manifest("templates/codeql/templates.json")

    def test_render_groups_locations_into_one_query(self) -> None:
        template = find_template(self.manifest, "find-constant-assignment-nearby")
        self.assertIsNotNone(template)
        requests = [
            {
                "request_id": "a",
                "template_id": template["id"],
                "parameters": {"file": "A.java", "line": 10},
            },
            {
                "request_id": "b",
                "template_id": template["id"],
                "parameters": {"file": "B.java", "line": 20},
            },
        ]

        rendered, window = render_batched_template(template, requests, "templates/codeql")

        self.assertNotIn("{{file}}", rendered)
        self.assertNotIn("{{line}}", rendered)
        self.assertIn('targetFile = "A.java" and targetLine = 10', rendered)
        self.assertIn('targetFile = "B.java" and targetLine = 20', rendered)
        self.assertIn("batchTarget(targetFile, targetLine)", rendered)
        self.assertEqual(window, (100, 120))

    def test_cache_key_is_parameter_order_independent(self) -> None:
        first = query_cache_key(
            database_hash="db",
            template_hash="template",
            parameters={"file": "A.java", "line": 10},
        )
        second = query_cache_key(
            database_hash="db",
            template_hash="template",
            parameters={"line": 10, "file": "A.java"},
        )
        self.assertEqual(first, second)

    def test_crypto_template_supports_batch_rendering(self) -> None:
        template = find_template(self.manifest, "find-crypto-algorithm")
        self.assertIsNotNone(template)

        rendered, window = render_batched_template(
            template,
            [
                {
                    "request_id": "crypto",
                    "template_id": template["id"],
                    "parameters": {"file": "Example.java", "line": 42},
                }
            ],
            "templates/codeql",
        )

        self.assertIn("batchTarget(targetFile, targetLine)", rendered)
        self.assertIn("crypto algorithm argument", rendered)
        self.assertEqual(window, (0, 0))

    def test_randomness_template_covers_source_before_sink(self) -> None:
        template = find_template(self.manifest, "find-randomness-source")
        self.assertIsNotNone(template)

        rendered, window = render_batched_template(
            template,
            [
                {
                    "request_id": "random",
                    "template_id": template["id"],
                    "parameters": {"file": "Example.java", "line": 76},
                }
            ],
            "templates/codeql",
        )

        self.assertIn("java.util.Random", rendered)
        self.assertIn("java.security.SecureRandom", rendered)
        self.assertEqual(window, (80, 30))


if __name__ == "__main__":
    unittest.main()
