from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from fpm_benchmark.llm import DeepSeekClient


class _Response:
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(
            {
                "choices": [{"message": {"content": '{"status":"ok"}'}}],
                "usage": {"total_tokens": 1},
            }
        ).encode("utf-8")


class DeepSeekClientTest(unittest.TestCase):
    def test_chat_request_has_openai_compatible_headers(self) -> None:
        client = DeepSeekClient(
            api_key="test-key",
            base_url="https://example.test/v1",
            model="deepseek-v4-flash",
            max_retries=0,
        )

        with patch("urllib.request.urlopen", return_value=_Response()) as urlopen:
            result, usage = client.chat_json([{"role": "user", "content": "health"}])

        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://example.test/v1/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key")
        self.assertEqual(request.get_header("Accept"), "application/json")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(
            request.get_header("User-agent"),
            "fpm-benchmark/0.1 (OpenAI-compatible API client)",
        )
        self.assertEqual(result, {"status": "ok"})
        self.assertEqual(usage, {"total_tokens": 1})


if __name__ == "__main__":
    unittest.main()
