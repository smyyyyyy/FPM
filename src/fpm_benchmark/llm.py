from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any


class DeepSeekClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str = "deepseek-v4-flash",
        timeout: int = 90,
        max_retries: int = 2,
    ) -> None:
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY")
        self.base_url = (base_url or os.environ.get("DEEPSEEK_BASE_URL") or "https://api.deepseek.com").rstrip("/")
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        if not self.api_key:
            raise RuntimeError("DEEPSEEK_API_KEY is not set")

    def chat_json(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0,
        max_tokens: int = 1200,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "fpm-benchmark/0.1 (OpenAI-compatible API client)",
            },
            method="POST",
        )
        last_error: Exception | None = None
        malformed_content = ""
        for attempt in range(self.max_retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = json.loads(response.read().decode("utf-8"))
                content = raw["choices"][0]["message"]["content"]
                try:
                    return extract_json_object(content), raw.get("usage", {})
                except ValueError as exc:
                    malformed_content = content
                    last_error = exc
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                if exc.code < 500 and exc.code != 429:
                    raise RuntimeError(f"DeepSeek API error {exc.code}: {body}") from exc
                last_error = RuntimeError(f"DeepSeek API error {exc.code}: {body}")
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = exc
            if attempt < self.max_retries:
                time.sleep(2**attempt)

        if malformed_content or isinstance(last_error, ValueError):
            parsed = {
                "verdict": "UNKNOWN",
                "confidence": "low",
                "sufficient": False,
                "missing_evidence": ["MALFORMED_LLM_OUTPUT"],
                "next_query": {"template_id": None, "parameters": {}, "reason": ""},
                "reason_summary": "LLM response was not valid JSON: " + malformed_content[:300],
            }
            return parsed, {}
        raise RuntimeError(f"DeepSeek API request failed after retries: {last_error}") from last_error


def extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        raise ValueError("LLM response did not contain a JSON object")
    obj = json.loads(m.group(0))
    if not isinstance(obj, dict):
        raise ValueError("LLM response JSON is not an object")
    return obj
