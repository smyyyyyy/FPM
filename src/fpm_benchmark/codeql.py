from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .query_templates import find_template, render_template


def execute_template_query(
    *,
    codeql_bin: str,
    database: str | Path,
    manifest: dict[str, Any],
    template_id: str,
    parameters: dict[str, Any],
    template_root: str | Path,
    output_dir: str | Path,
    additional_packs_root: str | Path | None = None,
) -> dict[str, Any]:
    template = find_template(manifest, template_id)
    if not template:
        return {"status": "failed", "error": f"Unknown template: {template_id}"}
    parameters = _normalize_parameters(template, parameters)
    missing = [
        name
        for name in template.get("parameters", [])
        if name not in parameters or parameters.get(name) in {None, ""}
    ]
    if missing:
        return {
            "status": "failed",
            "template_id": template_id,
            "parameters": parameters,
            "error": "Missing required template parameters: " + ", ".join(missing),
        }

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    rendered = render_template(template, parameters, template_root)

    with tempfile.TemporaryDirectory(prefix="fpm-codeql-") as tmp:
        tmp_path = Path(tmp)
        qlpack_path = tmp_path / "qlpack.yml"
        qlpack_path.write_text(
            'name: fpm/evidence-query\n'
            'version: 0.0.0\n'
            'dependencies:\n'
            '  codeql/java-all: "*"\n',
            encoding="utf-8",
        )
        query_path = tmp_path / f"{template_id}.ql"
        query_path.write_text(rendered, encoding="utf-8")
        bqrs_path = output_dir / f"{template_id}.bqrs"
        json_path = output_dir / f"{template_id}.json"
        command = [
            codeql_bin,
            "query",
            "run",
            str(query_path),
            "--database",
            str(database),
            "--output",
            str(bqrs_path),
        ]
        additional_packs = _additional_packs(additional_packs_root)
        if additional_packs:
            command.extend(["--additional-packs", additional_packs])

        run = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if run.returncode != 0:
            return {
                "status": "failed",
                "template_id": template_id,
                "error": run.stderr[-4000:],
                "stdout": run.stdout[-2000:],
            }

        decode = subprocess.run(
            [
                codeql_bin,
                "bqrs",
                "decode",
                str(bqrs_path),
                "--format",
                "json",
                "--output",
                str(json_path),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if decode.returncode != 0:
            return {
                "status": "failed",
                "template_id": template_id,
                "error": decode.stderr[-4000:],
                "stdout": decode.stdout[-2000:],
            }
        data = json.loads(json_path.read_text(encoding="utf-8"))
        return {
            "status": "ok",
            "template_id": template_id,
            "parameters": parameters,
            "result_path": str(json_path),
            "summary": summarize_bqrs_json(template_id, data),
            "result": data,
        }


def summarize_bqrs_json(template_id: str, data: dict[str, Any], max_facts: int = 20) -> dict[str, Any]:
    select = data.get("#select", {}) if isinstance(data, dict) else {}
    tuples = select.get("tuples", []) if isinstance(select, dict) else []
    facts: list[dict[str, Any]] = []
    seen_messages: set[str] = set()
    for row in tuples:
        if not isinstance(row, list):
            continue
        message = _row_message(row)
        if template_id == "find-static-field-call-context" and message in seen_messages:
            continue
        seen_messages.add(message)
        facts.append(
            {
                "message": message,
                "entities": [_entity_label(value) for value in row if isinstance(value, dict)],
                "values": [_scalar_value(value) for value in row if not isinstance(value, dict)],
            }
        )
        if len(facts) >= max_facts:
            break
    return {
        "template_id": template_id,
        "tuple_count": len(tuples),
        "facts": facts,
        "truncated": len(facts) >= max_facts and len(tuples) > len(facts),
        "absence_note": (
            "No rows were returned. Treat this as absence of queried evidence, not proof that "
            "the code has no sanitizer, guard, or safe API."
            if not tuples
            else ""
        ),
    }


def _normalize_parameters(template: dict[str, Any], parameters: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(parameters or {})
    for name in template.get("parameters", []):
        value = normalized.get(name)
        if "line" in name and isinstance(value, str) and value.strip().isdigit():
            normalized[name] = int(value.strip())
    return normalized


def _row_message(row: list[Any]) -> str:
    for value in reversed(row):
        if isinstance(value, str):
            return value
    return ""


def _entity_label(value: dict[str, Any]) -> str:
    label = value.get("label")
    if label is not None:
        return str(label)
    return str(value)


def _scalar_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _additional_packs(root: str | Path | None) -> str | None:
    if not root:
        default = Path.home() / ".codeql" / "packages" / "codeql"
        root = default if default.exists() else None
    if not root:
        return None
    root = Path(root)
    paths = [str(path.parent) for path in root.glob("*/*/qlpack.yml")]
    return ":".join(paths) if paths else None
