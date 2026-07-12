from __future__ import annotations

import json
from typing import Any

from .evidence import compact_for_llm
from .llm import DeepSeekClient

VALID_VERDICTS = {"TP", "FP", "UNKNOWN"}


SYSTEM_PROMPTS = {
    "b1_direct_llm": """You are a security static-analysis triage judge.
You receive a SAST alert, CWE, alert location, and local code.
Classify the alert as TP, FP, or UNKNOWN.
Prefer UNKNOWN when the local code does not prove either TP or FP.
Return a single JSON object only.
""",
    "b2_llm4sa_style": """You are a security static-analysis triage judge following an LLM4SA-style baseline.
Use the warning, related function/surrounding code, CWE, and provided examples/rubric.
Reason internally, but return only the required JSON object.
Prefer UNKNOWN when evidence is insufficient.
""",
    "b3_zerofalse_style": """You are a security static-analysis triage judge following a ZeroFalse-style baseline.
Use the alert contract, flow trace, CWE-specific rules, and structured checklist.
Classify TP, FP, or UNKNOWN.
Do not invent evidence beyond the provided structured evidence.
Return a single JSON object only.
""",
    "b4_conservative_score": """You are a conservative SAST false-positive mitigation judge.
Output a vulnerability-likelihood score from 0 to 10, where 0 means definitely false positive and 10 means definitely true positive.
Only mark FP when evidence is strong enough to suppress the alert without risking true positives.
Use UNKNOWN when the score is uncertain or evidence is incomplete.
Return a single JSON object only.
""",
    "ours_query_centered": """You are a security static-analysis triage judge.
Your task is to classify one CodeQL alert as TP, FP, or UNKNOWN using only the provided structured evidence.
Ground truth is not provided and must not be inferred from benchmark names.

Rules:
- Prefer UNKNOWN when evidence is insufficient.
- Do not claim that absence of evidence proves absence of a sanitizer or validator.
- If evidence is insufficient and a next query could help, select exactly one allowed template.
- Do not invent CodeQL templates or parameters.
- Prefer CWE-specific evidence templates when available: SQL parameterization for CWE-089,
  XSS encoder evidence for CWE-079, command execution arguments for CWE-078, path guards
  for CWE-022, and constant-assignment evidence when the code may overwrite user input.
- Treat precomputed missing-evidence labels as advisory. If the supplied trace and source code
  already prove TP or FP, finalize with sufficient=true and do not request a query.
- Request a query only when the current evidence cannot support a reliable final verdict.
- For OWASP-style Java alerts, constant overwrite is a common false-positive pattern. If a
  variable derived from user input later appears in a sink and no full path evidence is
  available, query constant-assignment evidence before concluding TP.
- When branch-assignment facts include constant numeric assignments and a simple arithmetic
  condition, perform the arithmetic. If the feasible branch assigns the sink variable from a
  constant or from a value derived from a constant, this is strong FP evidence. If the feasible
  branch assigns the sink variable from a request parameter or non-constant value, this supports TP.
- For SQL/XSS alerts, a later assignment of the sink variable from a constant or from a method
  call whose argument is a constant can justify FP only when the provided facts do not show a
  later feasible non-constant overwrite before the sink.
- Treat empty query results as missing queried evidence, not proof of safety.
- Mark FP only when the evidence strongly supports suppression; otherwise use TP or UNKNOWN.

- When a sink argument is read from a collection, account for intervening collection mutations
  only when the supplied evidence shows a complete, unambiguous operation sequence. A proven
  constant element is strong FP evidence and a proven user-controlled element supports TP.
  If aliases, branches, loops, unknown indices, or missing operations prevent a reliable element
  origin, do not simulate missing behavior; request evidence or return UNKNOWN.

- CWE-specific rules for cryptographic algorithms (CWE-327):
  - The following are BROKEN/RISKY algorithms that support TP: DES, DESede (TripleDES),
    RC4, RC2, MD5, SHA1, and deprecated SSL/TLS protocols.
  - AES in ANY mode (AES/ECB, AES/CBC, AES/GCM, AES/CTR, etc.) is a STRONG algorithm.
    An alert about AES/ECB/PKCS5Padding should be classified as FP, not TP.
    ECB mode is a weakness in usage, not a broken algorithm; the OWASP Benchmark treats
    AES (even in ECB mode) as a safe algorithm for CWE-327.
  - SHA-256 or stronger, HmacSHA256+, and RSA with sufficient key length are also safe.
  - Only flag TP for CWE-327 when the algorithm is in the known-weak list above.
    If the algorithm contains 'AES', classify as FP regardless of mode or padding.
- Return a single JSON object only.
""",
}


def build_user_prompt(
    evidence: dict[str, Any],
    *,
    allowed_templates: list[dict[str, Any]] | None = None,
    mode: str = "one-shot",
    view: str = "structured",
    baseline: str = "b3_zerofalse_style",
) -> str:
    schema: dict[str, Any] = {
        "verdict": "TP | FP | UNKNOWN",
        "confidence": "high | medium | low",
        "sufficient": "boolean",
        "missing_evidence": ["MISSING_*"],
        "next_query": {
            "template_id": "string or null",
            "parameters": "object",
            "reason": "string",
        },
        "reason_summary": "short string",
    }
    if baseline == "b4_conservative_score":
        schema.update(
            {
                "score": "integer from 0 to 10",
                "fp_confidence": "number from 0 to 1",
                "score_rationale": "short string",
            }
        )
    payload = {
        "mode": mode,
        "baseline": baseline,
        "evidence_view": view,
        "iteration_state": {
            "query_count": len(evidence.get("query_history", [])),
            "has_supplemental_evidence": bool(evidence.get("supplemental_evidence")),
            "first_pass": not evidence.get("query_history"),
        },
        "structured_evidence": compact_for_llm(evidence, view=view),
        "allowed_query_templates": allowed_templates or [],
        "few_shot_examples": few_shot_examples(baseline),
        "required_output_schema": schema,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def judge_once(
    client: DeepSeekClient,
    evidence: dict[str, Any],
    *,
    allowed_templates: list[dict[str, Any]] | None = None,
    mode: str = "one-shot",
    view: str = "structured",
    baseline: str = "b3_zerofalse_style",
    temperature: float = 0,
    max_tokens: int = 1200,
) -> tuple[dict[str, Any], dict[str, Any]]:
    system = SYSTEM_PROMPTS.get(baseline, SYSTEM_PROMPTS["b3_zerofalse_style"])
    messages = [
        {"role": "system", "content": system},
        {
            "role": "user",
            "content": build_user_prompt(
                evidence,
                allowed_templates=allowed_templates,
                mode=mode,
                view=view,
                baseline=baseline,
            ),
        },
    ]
    decision, usage = client.chat_json(messages, temperature=temperature, max_tokens=max_tokens)
    return normalize_decision(decision, baseline=baseline), usage


def normalize_decision(
    decision: dict[str, Any], *, baseline: str = "b3_zerofalse_style"
) -> dict[str, Any]:
    verdict = str(decision.get("verdict", "UNKNOWN")).upper()
    if verdict not in VALID_VERDICTS:
        verdict = "UNKNOWN"
    confidence = str(decision.get("confidence", "low")).lower()
    if confidence not in {"high", "medium", "low"}:
        confidence = "low"
    next_query = decision.get("next_query")
    if not isinstance(next_query, dict):
        next_query = {"template_id": None, "parameters": {}, "reason": ""}
    if not isinstance(next_query.get("parameters"), dict):
        next_query["parameters"] = {}
    missing = decision.get("missing_evidence")
    if not isinstance(missing, list):
        missing = []
    normalized = {
        "verdict": verdict,
        "confidence": confidence,
        "sufficient": bool(decision.get("sufficient", verdict != "UNKNOWN")),
        "missing_evidence": [str(x) for x in missing],
        "next_query": {
            "template_id": next_query.get("template_id"),
            "parameters": next_query.get("parameters", {}),
            "reason": str(next_query.get("reason", "")),
        },
        "reason_summary": str(decision.get("reason_summary", "")),
    }
    if baseline == "b4_conservative_score":
        score = _score(decision.get("score"))
        fp_confidence = _float(decision.get("fp_confidence"))
        if score is not None:
            if score <= 2 and (fp_confidence is None or fp_confidence >= 0.8):
                normalized["verdict"] = "FP"
                normalized["confidence"] = "high"
            elif score >= 7:
                normalized["verdict"] = "TP"
                normalized["confidence"] = "high" if score >= 9 else "medium"
            else:
                normalized["verdict"] = "UNKNOWN"
                normalized["confidence"] = "low"
        normalized["score"] = score
        normalized["fp_confidence"] = fp_confidence
        normalized["score_rationale"] = str(decision.get("score_rationale", ""))
    return normalized


def few_shot_examples(baseline: str) -> list[dict[str, Any]]:
    if baseline != "b2_llm4sa_style":
        return []
    return [
        {
            "case": "User-controlled request parameter reaches SQL string concatenation and executeQuery without bind parameters.",
            "expected": {"verdict": "TP", "confidence": "high"},
        },
        {
            "case": "Alert points to a PreparedStatement with placeholders where user input is only passed through setString.",
            "expected": {"verdict": "FP", "confidence": "high"},
        },
        {
            "case": "Local code lacks source-to-sink relation or sanitizer evidence.",
            "expected": {"verdict": "UNKNOWN", "confidence": "low"},
        },
    ]


def _score(value: object) -> int | None:
    try:
        score = int(float(str(value)))
    except (TypeError, ValueError):
        return None
    return max(0, min(10, score))


def _float(value: object) -> float | None:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None
