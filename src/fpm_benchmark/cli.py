from __future__ import annotations

import argparse
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .batch_codeql import execute_batched_template_queries
from .codeql import execute_template_query
from .dataset_summary import matched_records, summarize_labeled_evidence
from .diagnostic import (
    compare_diagnostic_decisions,
    force_diagnostic_evidence,
    select_diagnostic_cohort,
)
from .cwe_profiles import profile_for
from .evidence import enrich_core_evidence_slots
from .ground_truth import load_expected_results
from .judge import judge_once
from .llm import DeepSeekClient, LLMInfrastructureError
from .metrics import compute_metrics
from .query_templates import allowed_templates_for_llm, load_template_manifest
from .sarif import normalized_alerts_to_evidence, sarif_to_evidence
from .utils import read_json, read_jsonl, write_json, write_jsonl


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fpm-bench")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("parse-sarif", help="Convert CodeQL SARIF to structured evidence JSONL.")
    p.add_argument("--sarif", required=True)
    p.add_argument("--expected")
    p.add_argument("--source-root")
    p.add_argument("--out", required=True)
    p.add_argument("--config", default="configs/experiment.json")
    p.set_defaults(func=cmd_parse_sarif)

    p = sub.add_parser(
        "import-normalized",
        help="Convert normalized OWASP alert JSONL to structured evidence JSONL.",
    )
    p.add_argument("--input", required=True)
    p.add_argument("--expected")
    p.add_argument("--source-root")
    p.add_argument("--out", required=True)
    p.add_argument("--config", default="configs/experiment.json")
    p.set_defaults(func=cmd_import_normalized)

    p = sub.add_parser("llm-triage", help="Run DeepSeek TP/FP/Unknown triage.")
    p.add_argument("--input", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--config", default="configs/experiment.json")
    p.add_argument("--mode", choices=["one-shot", "iterative"], default="one-shot")
    p.add_argument(
        "--baseline",
        choices=[
            "b1_direct_llm",
            "b2_llm4sa_style",
            "b3_zerofalse_style",
            "b4_conservative_score",
            "b5_self_consistency",
            "ours_query_centered",
        ],
        default="b3_zerofalse_style",
    )
    p.add_argument(
        "--view",
        choices=[
            "auto",
            "raw-sarif",
            "direct",
            "llm4sa",
            "zerofalse",
            "source-chain",
            "query-centered",
            "structured",
        ],
        default="auto",
    )
    p.add_argument("--codeql-db")
    p.add_argument("--max-iterations", type=int)
    p.add_argument("--start", type=int, default=0)
    p.add_argument("--limit", type=int)
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--query-cache-dir", default="data/cache/codeql_queries")
    p.add_argument("--runtime-report")
    p.add_argument(
        "--resume",
        action="store_true",
        help="Resume an interrupted iterative run from decisions saved in --input.",
    )
    p.set_defaults(func=cmd_llm_triage)

    p = sub.add_parser("raw-codeql", help="Create a raw CodeQL baseline decision file.")
    p.add_argument("--input", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_raw_codeql)

    p = sub.add_parser("evaluate", help="Compute metrics from decisions JSONL.")
    p.add_argument("--decisions", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_evaluate)

    p = sub.add_parser(
        "dataset-summary",
        help="Audit alert-level ground truth and export matched evidence.",
    )
    p.add_argument("--input", required=True)
    p.add_argument("--expected")
    p.add_argument("--matched-out", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--config", default="configs/experiment.json")
    p.set_defaults(func=cmd_dataset_summary)

    p = sub.add_parser(
        "diagnostic-prepare",
        help="Build a paired error/control cohort and force the same CWE evidence queries.",
    )
    p.add_argument("--decisions", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--report", required=True)
    p.add_argument(
        "--no-evidence-out",
        help="Optionally save the selected cohort before forced queries for a matched control arm.",
    )
    p.add_argument("--config", default="configs/experiment.json")
    p.add_argument("--codeql-db")
    p.add_argument("--query-cache-dir", default="data/cache/diagnostic_queries")
    p.set_defaults(func=cmd_diagnostic_prepare)

    p = sub.add_parser(
        "diagnostic-compare",
        help="Compare forced-evidence decisions with their saved baseline decisions.",
    )
    p.add_argument("--decisions", required=True)
    p.add_argument("--control-decisions")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_diagnostic_compare)

    return args_run(parser.parse_args(argv))


def args_run(args: argparse.Namespace) -> int:
    args.func(args)
    return 0


def _build_llm_client(llm_cfg: dict[str, Any]) -> DeepSeekClient:
    key_env = str(llm_cfg.get("api_key_env", "DEEPSEEK_API_KEY"))
    api_key = os.environ.get(key_env)
    if not api_key:
        raise RuntimeError(f"{key_env} is not set")
    return DeepSeekClient(
        api_key=api_key,
        model=llm_cfg.get("model", "deepseek-v4-flash"),
        base_url=llm_cfg.get("base_url"),
        timeout=int(llm_cfg.get("timeout_seconds", 90)),
        max_retries=int(llm_cfg.get("max_retries", 2)),
        retry_concurrency=int(llm_cfg.get("retry_concurrency", 16)),
        retry_base_seconds=float(llm_cfg.get("retry_base_seconds", 2)),
        retry_max_seconds=float(llm_cfg.get("retry_max_seconds", 30)),
    )


def cmd_parse_sarif(args: argparse.Namespace) -> None:
    cfg = read_json(args.config)
    target_cwes = set(cfg.get("experiment", {}).get("target_cwes", []))
    records = sarif_to_evidence(
        args.sarif,
        expected_path=args.expected,
        source_root=args.source_root,
        target_cwes=target_cwes,
    )
    write_jsonl(args.out, records)
    print(f"wrote {len(records)} structured evidence records to {args.out}")


def cmd_import_normalized(args: argparse.Namespace) -> None:
    cfg = read_json(args.config)
    target_cwes = set(cfg.get("experiment", {}).get("target_cwes", []))
    records = normalized_alerts_to_evidence(
        args.input,
        expected_path=args.expected,
        source_root=args.source_root,
        target_cwes=target_cwes,
    )
    write_jsonl(args.out, records)
    print(f"wrote {len(records)} normalized structured evidence records to {args.out}")


def cmd_dataset_summary(args: argparse.Namespace) -> None:
    cfg = read_json(args.config)
    target_cwes = set(cfg.get("experiment", {}).get("target_cwes", []))
    records = read_jsonl(args.input)
    expected = load_expected_results(args.expected) if args.expected else None
    matched = matched_records(records)
    summary = summarize_labeled_evidence(records, target_cwes, expected)
    write_jsonl(args.matched_out, matched)
    write_json(args.out, summary)
    print(
        f"wrote {len(matched)} matched records to {args.matched_out}; "
        f"summary to {args.out}"
    )


def cmd_diagnostic_prepare(args: argparse.Namespace) -> None:
    cfg = read_json(args.config)
    codeql_cfg = cfg.get("codeql", {})
    database = args.codeql_db or codeql_cfg.get("database")
    if not database:
        raise ValueError("CodeQL database is required via --codeql-db or config")
    manifest_path = Path(codeql_cfg["template_manifest"])
    manifest = load_template_manifest(manifest_path)
    cohort, selection_report = select_diagnostic_cohort(read_jsonl(args.decisions))
    if args.no_evidence_out:
        write_jsonl(args.no_evidence_out, cohort)
    cohort, query_report = force_diagnostic_evidence(
        cohort,
        codeql_bin=codeql_cfg.get("codeql_bin", "codeql"),
        database=database,
        manifest=manifest,
        template_root=manifest_path.parent,
        cache_dir=args.query_cache_dir,
        additional_packs_root=codeql_cfg.get("additional_packs_root"),
    )
    write_jsonl(args.out, cohort)
    write_json(args.report, {"selection": selection_report, "queries": query_report})
    print(f"wrote {len(cohort)} diagnostic records to {args.out}")
    print(f"wrote diagnostic preparation report to {args.report}")


def cmd_diagnostic_compare(args: argparse.Namespace) -> None:
    controls = read_jsonl(args.control_decisions) if args.control_decisions else None
    report = compare_diagnostic_decisions(read_jsonl(args.decisions), controls)
    write_json(args.out, report)
    print(f"wrote diagnostic comparison to {args.out}")


def cmd_llm_triage(args: argparse.Namespace) -> None:
    cfg = read_json(args.config)
    llm_cfg = cfg.get("llm", {})
    codeql_cfg = cfg.get("codeql", {})
    experiment_cfg = cfg.get("experiment", {})
    records = read_jsonl(args.input)
    if args.start:
        records = records[args.start :]
    if args.limit:
        records = records[: args.limit]

    manifest = load_template_manifest(codeql_cfg["template_manifest"])
    allowed = allowed_templates_for_llm(manifest)
    max_iterations = args.max_iterations or int(experiment_cfg.get("max_iterations", 3))

    if args.mode == "iterative":
        args.baseline = "ours_query_centered"
        _cmd_llm_triage_iterative_batched(
            args=args,
            cfg=cfg,
            records=records,
            manifest=manifest,
            allowed=allowed,
            max_iterations=max_iterations,
        )
        return

    client = _build_llm_client(llm_cfg)

    if args.workers > 1 and args.mode == "one-shot":
        _cmd_llm_triage_parallel(args, cfg, records, allowed)
        return

    decisions: list[dict[str, Any]] = []
    for idx, evidence in enumerate(records, start=1):
        start = time.time()
        usages: list[dict[str, Any]] = []
        iterations = 1 if args.mode == "one-shot" else max_iterations

        for iteration in range(iterations):
            decision, usage, trace = _judge_for_baseline(
                client=client,
                evidence=evidence,
                allowed=allowed if args.mode == "iterative" else [],
                args=args,
                llm_cfg=llm_cfg,
            )
            usages.append(usage)
            evidence["decision"] = decision
            for trace_item in trace:
                trace_item["iteration"] = iteration + 1
                evidence.setdefault("llm_trace", []).append(trace_item)

            if args.mode == "one-shot":
                break

            next_query = _controller_next_query(
                evidence=evidence,
                decision=decision,
                can_continue=iteration + 1 < iterations,
            )
            if decision["verdict"] in {"TP", "FP"} and not next_query:
                break
            template_id = next_query.get("template_id")
            if not template_id:
                break

            query_record = {
                "iteration": iteration + 1,
                "template_id": template_id,
                "parameters": next_query.get("parameters", {}),
                "reason": next_query.get("reason", ""),
            }
            if not args.codeql_db:
                query_record["status"] = "not_executed_no_codeql_db"
                evidence.setdefault("query_history", []).append(query_record)
                break

            result = execute_template_query(
                codeql_bin=codeql_cfg.get("codeql_bin", "codeql"),
                database=args.codeql_db,
                manifest=manifest,
                template_id=template_id,
                parameters=next_query.get("parameters", {}),
                template_root=Path(codeql_cfg["template_manifest"]).parent,
                output_dir="data/interim/query_results",
                additional_packs_root=codeql_cfg.get("additional_packs_root"),
            )
            query_record.update(result)
            evidence.setdefault("query_history", []).append(query_record)
            evidence.setdefault("supplemental_evidence", []).append(result)

        evidence["runtime_seconds"] = time.time() - start
        evidence["llm_usage_total"] = _sum_usage(usages)
        decisions.append(evidence)
        write_jsonl(args.out, decisions)
        print(f"[{idx}/{len(records)}] {evidence['alert_id']} -> {evidence['decision']['verdict']}")

    write_jsonl(args.out, decisions)
    print(f"wrote {len(decisions)} decisions to {args.out}")


def _cmd_llm_triage_parallel(
    args: argparse.Namespace,
    cfg: dict[str, Any],
    records: list[dict[str, Any]],
    allowed: list[dict[str, Any]],
) -> None:
    llm_cfg = cfg.get("llm", {})
    decisions_by_index: dict[int, dict[str, Any]] = {}

    def run_one(index_record: tuple[int, dict[str, Any]]) -> tuple[int, dict[str, Any]]:
        index, evidence = index_record
        start = time.time()
        try:
            client = _build_llm_client(llm_cfg)
            decision, usage, trace = _judge_for_baseline(
                client=client,
                evidence=evidence,
                allowed=[],
                args=args,
                llm_cfg=llm_cfg,
            )
            evidence["decision"] = decision
            evidence.setdefault("llm_trace", []).extend(trace)
            evidence["llm_usage_total"] = _sum_usage([usage])
        except Exception as exc:
            evidence["decision"] = {
                "verdict": "INFRA_ERROR",
                "confidence": "low",
                "sufficient": False,
                "missing_evidence": ["LLM_CALL_FAILED"],
                "next_query": {"template_id": None, "parameters": {}, "reason": ""},
                "reason_summary": f"LLM call failed: {exc}",
            }
            evidence["llm_error"] = str(exc)
            evidence["infrastructure_error"] = {
                "type": getattr(exc, "error_type", "client_error"),
                "attempts": getattr(exc, "attempts", 1),
                "retryable": getattr(exc, "retryable", False),
            }
        evidence["runtime_seconds"] = time.time() - start
        return index, evidence

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(run_one, item) for item in enumerate(records, start=1)]
        for future in as_completed(futures):
            index, evidence = future.result()
            decisions_by_index[index] = evidence
            ordered = [decisions_by_index[i] for i in sorted(decisions_by_index)]
            write_jsonl(args.out, ordered)
            print(
                f"[{len(decisions_by_index)}/{len(records)}] "
                f"{evidence['alert_id']} -> {evidence['decision']['verdict']}"
            )

    print(f"wrote {len(decisions_by_index)} decisions to {args.out}")


def _cmd_llm_triage_iterative_batched(
    *,
    args: argparse.Namespace,
    cfg: dict[str, Any],
    records: list[dict[str, Any]],
    manifest: dict[str, Any],
    allowed: list[dict[str, Any]],
    max_iterations: int,
) -> None:
    run_started = time.perf_counter()
    llm_cfg = cfg.get("llm", {})
    codeql_cfg = cfg.get("codeql", {})
    completed_iterations = 0
    if args.resume:
        completed_iterations = max(
            (
                int(item.get("iteration", 0))
                for record in records
                for item in record.get("llm_trace", [])
            ),
            default=0,
        )
        pending = [
            index
            for index, record in enumerate(records)
            if not _decision_is_final(record.get("decision", {}), record)
        ]
        ready_after_query = {
            index
            for index, record in enumerate(records)
            if any(
                int(item.get("iteration", 0)) == completed_iterations
                for item in record.get("query_history", [])
            )
        }
        active = [index for index in pending if index in ready_after_query]
        for index in pending:
            if index not in ready_after_query:
                records[index]["decision"] = _unresolved_decision(records[index]["decision"])
    else:
        active = list(range(len(records)))
    llm_rounds: list[dict[str, Any]] = []
    query_rounds: list[dict[str, Any]] = []
    queried_alerts: set[int] = {
        index for index, record in enumerate(records) if record.get("query_history")
    }
    direct_after_first_round = sum(
        1
        for record in records
        if len(record.get("llm_trace", [])) == 1
        and _decision_is_final(record.get("decision", {}), record)
    ) if args.resume else 0

    for record in records:
        enrich_core_evidence_slots(record)
        record.setdefault("llm_usage_total", {})
        record.setdefault("runtime_breakdown", {"llm_seconds": 0.0, "query_count": 0})

    for iteration in range(completed_iterations, max_iterations):
        if not active:
            break
        round_started = time.perf_counter()
        round_results: dict[
            int,
            tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], float],
        ] = {}

        def run_one(
            index: int,
        ) -> tuple[int, dict[str, Any], dict[str, Any], list[dict[str, Any]], float]:
            started = time.perf_counter()
            try:
                client = _build_llm_client(llm_cfg)
                decision, usage, trace = _judge_for_baseline(
                    client=client,
                    evidence=records[index],
                    allowed=allowed,
                    args=args,
                    llm_cfg=llm_cfg,
                )
            except Exception as exc:
                error_type = exc.error_type if isinstance(exc, LLMInfrastructureError) else "client_error"
                attempts = exc.attempts if isinstance(exc, LLMInfrastructureError) else 1
                decision = {
                    "verdict": "INFRA_ERROR",
                    "confidence": "low",
                    "sufficient": False,
                    "missing_evidence": ["LLM_CALL_FAILED"],
                    "next_query": {"template_id": None, "parameters": {}, "reason": ""},
                    "reason_summary": f"LLM call failed: {exc}",
                }
                usage = {}
                trace = [{"decision": decision, "usage": usage, "baseline": args.baseline}]
                records[index]["llm_error"] = str(exc)
                records[index]["infrastructure_error"] = {
                    "type": error_type,
                    "attempts": attempts,
                    "retryable": getattr(exc, "retryable", False),
                }
            return index, decision, usage, trace, time.perf_counter() - started

        workers = max(1, args.workers)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(run_one, index) for index in active]
            for future in as_completed(futures):
                index, decision, usage, trace, duration = future.result()
                round_results[index] = (decision, usage, trace, duration)
                print(
                    f"[round {iteration + 1} {len(round_results)}/{len(active)}] "
                    f"{records[index]['alert_id']} -> {decision['verdict']}"
                )

        next_requests: list[dict[str, Any]] = []
        request_to_index: dict[str, int] = {}
        finalized = 0
        for index in active:
            evidence = records[index]
            decision, usage, trace, duration = round_results[index]
            evidence["llm_usage_total"] = _sum_usage([evidence.get("llm_usage_total", {}), usage])
            evidence["runtime_breakdown"]["llm_seconds"] += duration
            for trace_item in trace:
                trace_item["iteration"] = iteration + 1
                evidence.setdefault("llm_trace", []).append(trace_item)

            if _decision_is_call_failure(decision):
                evidence["last_failed_decision"] = decision
                # A failed re-judgment does not validate an earlier candidate
                # that failed the gate. Keep it for diagnosis only.
                previous = evidence.get("decision")
                if isinstance(previous, dict) and not _decision_is_call_failure(previous):
                    evidence["pre_failure_decision"] = previous
                evidence["decision"] = decision
                finalized += 1
                continue

            evidence["decision"] = decision

            if _decision_is_final(decision, evidence):
                finalized += 1
                if iteration == 0:
                    direct_after_first_round += 1
                continue
            if iteration + 1 >= max_iterations:
                evidence["decision"] = _unresolved_decision(decision)
                finalized += 1
                continue

            # LLM reported sufficient but checklist gate failed, or LLM
            # reported insufficient. Try LLM's requested query first.
            if decision.get("next_query", {}).get("template_id"):
                next_query = decision["next_query"]
            else:
                next_query = _controller_next_query(
                    evidence=evidence,
                    decision=decision,
                    can_continue=True,
                )
            next_query = _normalize_query_request(next_query, evidence, manifest)
            template_id = next_query.get("template_id")
            if not template_id:
                evidence["decision"] = _unresolved_decision(decision)
                finalized += 1
                continue
            request_id = f"{index}:{iteration + 1}"
            request = {
                "request_id": request_id,
                "template_id": template_id,
                "parameters": next_query.get("parameters", {}),
            }
            next_requests.append(request)
            request_to_index[request_id] = index

        llm_rounds.append(
            {
                "round": iteration + 1,
                "input_alerts": len(active),
                "finalized": finalized,
                "query_requests": len(next_requests),
                "wall_seconds": time.perf_counter() - round_started,
            }
        )
        write_jsonl(args.out, records)
        if not next_requests:
            active = []
            break
        if not args.codeql_db:
            for request in next_requests:
                index = request_to_index[request["request_id"]]
                records[index].setdefault("query_history", []).append(
                    {
                        "iteration": iteration + 1,
                        **request,
                        "status": "not_executed_no_codeql_db",
                    }
                )
            active = []
            break

        batch_results, batch_stats = execute_batched_template_queries(
            requests=next_requests,
            codeql_bin=codeql_cfg.get("codeql_bin", "codeql"),
            database=args.codeql_db,
            manifest=manifest,
            template_root=Path(codeql_cfg["template_manifest"]).parent,
            cache_dir=args.query_cache_dir,
            additional_packs_root=codeql_cfg.get("additional_packs_root"),
        )
        batch_stats["round"] = iteration + 1
        query_rounds.append(batch_stats)
        active = []
        for request in next_requests:
            index = request_to_index[request["request_id"]]
            result = batch_results[request["request_id"]]
            query_record = {
                "iteration": iteration + 1,
                "template_id": request["template_id"],
                "parameters": request.get("parameters", {}),
                "reason": records[index]["decision"].get("next_query", {}).get("reason", ""),
            }
            query_record.update(result)
            records[index].setdefault("query_history", []).append(query_record)
            records[index].setdefault("supplemental_evidence", []).append(result)
            _update_slots_from_query(records[index], result)
            records[index]["runtime_breakdown"]["query_count"] += 1
            queried_alerts.add(index)
            active.append(index)
        write_jsonl(args.out, records)

    for record in records:
        record["runtime_seconds"] = record.get("runtime_breakdown", {}).get("llm_seconds", 0.0)
    write_jsonl(args.out, records)
    report_path = args.runtime_report or f"{args.out}.runtime.json"
    verdict_counts: dict[str, int] = {}
    for record in records:
        verdict = str(record.get("decision", {}).get("verdict", "UNKNOWN"))
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
    query_requests = sum(item.get("requests", 0) for item in query_rounds)
    cache_hits = sum(item.get("cache_hits", 0) for item in query_rounds)
    cache_misses = sum(item.get("cache_misses", 0) for item in query_rounds)
    runtime_report = {
        "mode": "iterative_batched",
        "resumed": bool(args.resume),
        "resume_start_iteration": completed_iterations if args.resume else None,
        "alerts": len(records),
        "workers": max(1, args.workers),
        "max_iterations": max_iterations,
        "wall_seconds": time.perf_counter() - run_started,
        "direct_after_first_round": direct_after_first_round,
        "queried_alerts": len(queried_alerts),
        "verdict_counts": verdict_counts,
        "infrastructure_errors": verdict_counts.get("INFRA_ERROR", 0),
        "llm_rounds": llm_rounds,
        "query": {
            "requests": query_requests,
            "cache_hits": cache_hits,
            "cache_misses": cache_misses,
            "cache_hit_rate": cache_hits / query_requests if query_requests else None,
            "batch_count": sum(item.get("batch_count", 0) for item in query_rounds),
            "wall_seconds": sum(item.get("wall_seconds", 0.0) for item in query_rounds),
            "rounds": query_rounds,
        },
    }
    write_json(report_path, runtime_report)
    print(f"wrote {len(records)} decisions to {args.out}")
    print(f"wrote runtime report to {report_path}")


def _judge_for_baseline(
    *,
    client: DeepSeekClient,
    evidence: dict[str, Any],
    allowed: list[dict[str, Any]],
    args: argparse.Namespace,
    llm_cfg: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    baseline = args.baseline
    view = _effective_view(args.view, baseline)
    temperature = float(llm_cfg.get("temperature", 0))
    max_tokens = int(llm_cfg.get("max_output_tokens", 1200))

    if baseline != "b5_self_consistency":
        decision, usage = judge_once(
            client,
            evidence,
            allowed_templates=allowed,
            mode=args.mode,
            view=view,
            baseline=baseline,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return decision, usage, [{"decision": decision, "usage": usage, "baseline": baseline}]

    votes: list[dict[str, Any]] = []
    usages: list[dict[str, Any]] = []
    repeat_count = max(1, args.repeats)
    for repeat_index in range(repeat_count):
        decision, usage = judge_once(
            client,
            evidence,
            allowed_templates=[],
            mode="one-shot",
            view=_effective_view("auto", "b4_conservative_score"),
            baseline="b4_conservative_score",
            temperature=max(temperature, 0.7),
            max_tokens=max_tokens,
        )
        votes.append(decision)
        usages.append(usage)

    verdicts = [vote["verdict"] for vote in votes]
    if all(verdict == "FP" for verdict in verdicts):
        final_verdict = "FP"
        confidence = "high"
    elif all(verdict == "TP" for verdict in verdicts):
        final_verdict = "TP"
        confidence = "high"
    else:
        final_verdict = "UNKNOWN"
        confidence = "low"

    final = {
        "verdict": final_verdict,
        "confidence": confidence,
        "sufficient": final_verdict != "UNKNOWN",
        "missing_evidence": [] if final_verdict != "UNKNOWN" else ["SELF_CONSISTENCY_DISAGREEMENT"],
        "next_query": {"template_id": None, "parameters": {}, "reason": ""},
        "reason_summary": "Self-consistency votes: " + ", ".join(verdicts),
        "votes": votes,
    }
    return final, _sum_usage(usages), [
        {"decision": vote, "usage": usage, "baseline": "b4_conservative_score", "repeat": i + 1}
        for i, (vote, usage) in enumerate(zip(votes, usages, strict=False))
    ]


def _effective_view(view: str, baseline: str) -> str:
    if view != "auto":
        return view
    mapping = {
        "b1_direct_llm": "direct",
        "b2_llm4sa_style": "llm4sa",
        "b3_zerofalse_style": "zerofalse",
        "b4_conservative_score": "zerofalse",
        "b5_self_consistency": "zerofalse",
        "ours_query_centered": "zerofalse",
    }
    return mapping.get(baseline, "zerofalse")


def _controller_next_query(
    *,
    evidence: dict[str, Any],
    decision: dict[str, Any],
    can_continue: bool,
) -> dict[str, Any]:
    if not can_continue:
        return {"template_id": None, "parameters": {}, "reason": ""}
    if _decision_is_final(decision, evidence):
        return {"template_id": None, "parameters": {}, "reason": ""}
    next_query = decision.get("next_query")
    if isinstance(next_query, dict) and next_query.get("template_id"):
        return next_query
    mandatory = _next_mandatory_query(evidence)
    if mandatory:
        return mandatory
    return {"template_id": None, "parameters": {}, "reason": ""}


def _decision_is_final(decision: dict[str, Any], evidence: dict[str, Any] | None = None) -> bool:
    if decision.get("verdict") not in {"TP", "FP"} or decision.get("sufficient") is not True:
        return False
    if evidence is None:
        return True
    if not _decision_is_semantically_consistent(decision, evidence):
        return False
    return _checklist_gate_satisfied(
        evidence,
        str(decision.get("verdict")),
        str(decision.get("confidence", "low")),
    )


def _decision_is_semantically_consistent(
    decision: dict[str, Any], evidence: dict[str, Any]
) -> bool:
    cwe = evidence.get("alert_contract", {}).get("cwe")
    verdict = decision.get("verdict")
    slots = evidence.get("evidence_slots", {})
    if cwe == "CWE-327":
        if verdict == "FP" and slots.get("known_weak_api_or_algorithm") == "yes":
            return False
        if verdict == "TP" and slots.get("known_strong_algorithm") == "yes":
            return False
    if (
        cwe == "CWE-501"
        and verdict == "FP"
        and slots.get("source_user_controlled") == "yes"
        and slots.get("trust_boundary_crossing") == "yes"
        and slots.get("validator_present") != "yes"
    ):
        return False
    return True


def _decision_is_call_failure(decision: dict[str, Any]) -> bool:
    missing = decision.get("missing_evidence", [])
    return isinstance(missing, list) and "LLM_CALL_FAILED" in missing


def _unresolved_decision(decision: dict[str, Any]) -> dict[str, Any]:
    missing = decision.get("missing_evidence", [])
    unresolved = list(missing) if isinstance(missing, list) else []
    if "MAX_ITERATIONS_WITHOUT_SUFFICIENT_EVIDENCE" not in unresolved:
        unresolved.append("MAX_ITERATIONS_WITHOUT_SUFFICIENT_EVIDENCE")
    return {
        "verdict": "UNKNOWN",
        "confidence": "low",
        "sufficient": False,
        "missing_evidence": unresolved,
        "next_query": {"template_id": None, "parameters": {}, "reason": ""},
        "reason_summary": "Maximum evidence rounds reached without satisfying the sufficiency gate.",
        "candidate_decision": decision,
    }


TP_REQUIRED_SLOTS: dict[str, tuple[str, ...]] = {
    "CWE-022": ("source_user_controlled", "sink_dangerous", "path_exists"),
    "CWE-078": ("source_user_controlled", "sink_dangerous", "path_exists"),
    "CWE-079": ("source_user_controlled", "sink_dangerous", "path_exists"),
    "CWE-089": ("source_user_controlled", "sink_dangerous", "path_exists"),
    "CWE-090": ("source_user_controlled", "sink_dangerous", "path_exists"),
    "CWE-327": ("api_identified", "argument_extracted", "known_weak_api_or_algorithm"),
    "CWE-330": ("api_identified", "randomness_source_known"),
    "CWE-501": ("source_user_controlled", "trust_boundary_crossing"),
    "CWE-614": ("cookie_created", "secure_flag_checked"),
    "CWE-643": ("source_user_controlled", "sink_dangerous", "path_exists"),
}

FP_EVIDENCE_SLOTS: dict[str, tuple[str, ...]] = {
    "CWE-022": ("validator_present", "constant_overwrite", "sink_argument_origin"),
    "CWE-078": ("sanitizer_present", "constant_overwrite", "sink_argument_origin"),
    "CWE-079": (
        "sanitizer_present",
        "framework_semantics_known",
        "constant_overwrite",
        "sink_argument_origin",
    ),
    "CWE-089": ("safe_api_usage", "sink_argument_origin", "constant_overwrite"),
    "CWE-090": ("sanitizer_present", "validator_present", "constant_overwrite"),
    "CWE-327": ("known_strong_algorithm",),
    "CWE-330": ("randomness_source_known",),
    "CWE-501": ("validator_present",),
    "CWE-614": ("secure_flag_set",),
    "CWE-643": ("sanitizer_present", "validator_present", "constant_overwrite"),
}

FP_REQUIRED_SLOTS: dict[str, tuple[str, ...]] = {
    "CWE-022": ("sink_identified",),
    "CWE-078": ("sink_identified",),
    "CWE-079": ("sink_identified",),
    "CWE-089": ("sink_identified",),
    "CWE-090": ("sink_identified",),
    "CWE-327": ("api_identified",),
    "CWE-330": ("api_identified",),
    "CWE-501": ("source_identified",),
    "CWE-614": ("cookie_created",),
    "CWE-643": ("sink_identified",),
}

FP_EVIDENCE_TEMPLATES: dict[str, set[str]] = {
    "CWE-022": {"find-path-canonical-guard", "find-constant-assignment-nearby"},
    "CWE-078": {"find-command-execution-arguments", "find-constant-assignment-nearby"},
    "CWE-079": {"find-xss-encoder-nearby", "find-constant-assignment-nearby"},
    "CWE-089": {"find-sql-parameterization", "find-constant-assignment-nearby"},
    "CWE-090": {"find-sanitizer-on-path", "find-constant-assignment-nearby"},
    "CWE-327": {"find-crypto-algorithm"},
    "CWE-330": {"find-randomness-source"},
    "CWE-501": {"find-validator-or-guard"},
    "CWE-614": {"find-cookie-secure-flag"},
    "CWE-643": {"find-sanitizer-on-path", "find-constant-assignment-nearby"},
}


def _checklist_gate_satisfied(
    evidence: dict[str, Any], verdict: str = "TP", confidence: str = "low"
) -> bool:
    """Apply CWE- and verdict-specific sufficiency requirements."""
    cwe = evidence.get("alert_contract", {}).get("cwe")
    slots = evidence.get("evidence_slots", {})
    checklist = profile_for(cwe).get("sufficiency_checklist", [])
    if any(slots.get(slot) in {"error", "checked_error"} for slot in checklist):
        return False

    if verdict == "TP":
        required = TP_REQUIRED_SLOTS.get(str(cwe), ())
        return all(slots.get(slot) == "yes" for slot in required)
    if verdict != "FP":
        return False

    required = FP_REQUIRED_SLOTS.get(str(cwe), ())
    if any(slots.get(slot) != "yes" for slot in required):
        return False
    resolved_states = {"yes"}
    if any(slots.get(slot) in resolved_states for slot in FP_EVIDENCE_SLOTS.get(str(cwe), ())):
        return True
    successful_templates = {
        str(item.get("template_id"))
        for item in evidence.get("query_history", [])
        if item.get("status") in {"ok", "empty"}
    }
    trace = evidence.get("annotated_trace", [])
    complete_trace = (
        len(trace) >= 2
        and trace[0].get("role") == "SOURCE_CANDIDATE"
        and trace[-1].get("role") == "SINK_CANDIDATE"
    )
    # Nearby calls, guards, or assignments are candidates for LLM reasoning,
    # not proof that the same value was sanitized or overwritten on the path.
    return confidence == "high" and complete_trace and bool(
        successful_templates & FP_EVIDENCE_TEMPLATES.get(str(cwe), set())
    )


def _normalize_query_request(
    query: dict[str, Any], evidence: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    template_id = query.get("template_id")
    template = next(
        (
            item
            for item in manifest.get("templates", [])
            if item.get("id") == template_id and item.get("enabled", True) is not False
        ),
        None,
    )
    if not template:
        fallback = _next_mandatory_query(evidence)
        return fallback or {"template_id": None, "parameters": {}, "reason": ""}
    parameters = dict(query.get("parameters") or {})
    location = _location_query_params(evidence) or {}
    for name in template.get("parameters", []):
        if name not in parameters and name in location:
            parameters[name] = location[name]
    if any(parameters.get(name) in {None, ""} for name in template.get("parameters", [])):
        fallback = _next_mandatory_query(evidence)
        return fallback or {"template_id": None, "parameters": {}, "reason": ""}
    return {
        "template_id": template_id,
        "parameters": parameters,
        "reason": str(query.get("reason", "")),
    }


def _next_mandatory_query(evidence: dict[str, Any]) -> dict[str, Any] | None:
    cwe = evidence.get("alert_contract", {}).get("cwe")
    sequence_by_cwe = {
        "CWE-089": ["find-sql-parameterization", "find-constant-assignment-nearby"],
        "CWE-079": ["find-xss-encoder-nearby", "find-constant-assignment-nearby"],
        "CWE-078": ["find-command-execution-arguments", "find-constant-assignment-nearby"],
        "CWE-022": ["find-path-canonical-guard", "find-constant-assignment-nearby"],
        "CWE-090": ["find-sanitizer-on-path", "find-constant-assignment-nearby"],
        "CWE-327": ["find-crypto-algorithm"],
        "CWE-330": ["find-randomness-source"],
        "CWE-501": ["find-trust-boundary-transfer"],
        "CWE-614": ["find-cookie-secure-flag"],
        "CWE-643": ["find-constant-assignment-nearby"],
    }
    sequence = sequence_by_cwe.get(cwe, [])
    if not sequence:
        return None
    existing = {item.get("template_id") for item in evidence.get("query_history", [])}
    params = _location_query_params(evidence)
    if not params:
        return None
    for template_id in sequence:
        if template_id not in existing:
            return {
                "template_id": template_id,
                "parameters": params,
                "reason": "controller mandatory query for query-centered evidence completeness",
            }
    return None


SLOT_UPDATE_BY_TEMPLATE: dict[str, dict[str, str]] = {
    "find-crypto-algorithm": {
        "api_identified": "yes",
        "argument_extracted": "yes",
    },
    "find-randomness-source": {
        "api_identified": "yes",
        "randomness_source_known": "yes",
    },
    "find-sql-parameterization": {
        "sink_argument_origin": "yes",
    },
    "find-sql-sink-and-construction": {
        "sink_argument_origin": "yes",
    },
    "find-constant-assignment-nearby": {
        "nearby_constant_assignment_found": "yes",
    },
    "find-xss-encoder-nearby": {
        "nearby_sanitizer_found": "yes",
    },
    "find-command-execution-arguments": {
        "sink_argument_origin": "yes",
    },
    "find-path-canonical-guard": {
        "nearby_validator_found": "yes",
    },
    "find-validator-or-guard": {
        "nearby_validator_found": "yes",
    },
    "find-sanitizer-on-path": {
        "nearby_sanitizer_found": "yes",
    },
    "find-sink-argument-origin": {
        "sink_argument_origin": "yes",
    },
    "find-source-origin": {
        "source_user_controlled": "yes",
    },
    "find-source-to-sink-path": {
        "path_exists": "yes",
    },
    "find-cookie-secure-flag": {
        "cookie_created": "yes",
        "secure_flag_checked": "yes",
    },
    "find-trust-boundary-transfer": {
        "trust_boundary_crossing": "yes",
    },
}


def _update_slots_from_query(evidence: dict[str, Any], result: dict[str, Any]) -> None:
    """Update evidence_slots based on query result so checklist gate can progress."""
    template_id = result.get("template_id", "")
    updates = SLOT_UPDATE_BY_TEMPLATE.get(template_id, {})
    slots = evidence.setdefault("evidence_slots", {})
    status = result.get("status", "")
    tuple_count = result.get("summary", {}).get("tuple_count", 0) if isinstance(result.get("summary"), dict) else 0
    if status == "ok" and tuple_count and tuple_count > 0:
        for slot, value in updates.items():
            if slots.get(slot) in {None, "unknown", "no"}:
                slots[slot] = value
        if template_id == "find-sql-parameterization" and _sql_query_proves_safe_usage(result):
            slots["safe_api_usage"] = "yes"
        if template_id == "find-crypto-algorithm":
            algorithm_class = _classify_crypto_algorithm(evidence, result)
            if algorithm_class == "weak":
                slots["known_weak_api_or_algorithm"] = "yes"
                slots["known_strong_algorithm"] = "no"
            elif algorithm_class == "strong":
                slots["known_weak_api_or_algorithm"] = "no"
                slots["known_strong_algorithm"] = "yes"
    elif status == "ok" and tuple_count == 0:
        # Query ran but found nothing. A non-empty query result was
        # still produced (e.g., "no sanitizer found"), so mark the
        # slot as "checked_none" rather than leaving it "unknown".
        for slot, value in updates.items():
            if slots.get(slot) in {None, "unknown"}:
                slots[slot] = "checked_none"
    elif status == "empty":
        for slot, value in updates.items():
            if slots.get(slot) in {None, "unknown"}:
                slots[slot] = "checked_none"
    else:
        # Preserve the distinction between missing evidence and failed collection.
        for slot, value in updates.items():
            if slots.get(slot) in {None, "unknown"}:
                slots[slot] = "error"


def _sql_query_proves_safe_usage(result: dict[str, Any]) -> bool:
    summary = result.get("summary", {})
    facts = summary.get("facts", []) if isinstance(summary, dict) else []
    messages = "\n".join(str(fact.get("message", "")) for fact in facts)
    if re.search(r"method=set(?:String|Int|Long|Object)\b", messages):
        return True
    return bool(
        re.search(
            r"method=prepareStatement\b[^\n]*arg_compile_time_constant=yes",
            messages,
        )
    )


def _classify_crypto_algorithm(evidence: dict[str, Any], result: dict[str, Any]) -> str | None:
    trace_text = "\n".join(
        str(item.get("code", "")) + " " + str(item.get("message", ""))
        for item in evidence.get("annotated_trace", [])
    )
    summary = result.get("summary", {})
    facts = summary.get("facts", []) if isinstance(summary, dict) else []
    fact_text = "\n".join(str(item.get("message", "")) for item in facts)
    text = trace_text + "\n" + fact_text
    if re.search(r"(?i)\b(?:DESede|TripleDES|DES|RC4|RC2|MD5|SHA-?1)\b", text):
        return "weak"
    if re.search(r"(?i)\b(?:AES|SHA-?(?:256|384|512)|HmacSHA(?:256|384|512))\b", text):
        return "strong"
    return None


def _location_query_params(evidence: dict[str, Any]) -> dict[str, Any] | None:
    primary = evidence.get("alert_contract", {}).get("primary_location", {})
    file = primary.get("file") or primary.get("uri")
    line = primary.get("start_line")
    if not file or line in {None, ""}:
        return None
    return {"file": file, "line": line}


def cmd_raw_codeql(args: argparse.Namespace) -> None:
    records = read_jsonl(args.input)
    for evidence in records:
        evidence["decision"] = {
            "verdict": "TP",
            "confidence": "baseline",
            "sufficient": True,
            "missing_evidence": [],
            "next_query": {"template_id": None, "parameters": {}, "reason": ""},
            "reason_summary": "Raw CodeQL baseline treats every reported alert as kept.",
        }
    write_jsonl(args.out, records)
    print(f"wrote raw CodeQL baseline decisions to {args.out}")


def _sum_usage(usages: list[dict[str, Any]]) -> dict[str, int]:
    total: dict[str, int] = {}
    for usage in usages:
        for key, value in usage.items():
            if isinstance(value, int):
                total[key] = total.get(key, 0) + value
    return total


def cmd_evaluate(args: argparse.Namespace) -> None:
    records = read_jsonl(args.decisions)
    metrics = compute_metrics(records)
    write_json(args.out, metrics)
    print(f"wrote metrics to {args.out}")


if __name__ == "__main__":
    raise SystemExit(main())
