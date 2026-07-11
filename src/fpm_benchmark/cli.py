from __future__ import annotations

import argparse
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
from .ground_truth import load_expected_results
from .judge import judge_once
from .llm import DeepSeekClient
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

    client = DeepSeekClient(
        model=llm_cfg.get("model", "deepseek-v4-flash"),
        base_url=llm_cfg.get("base_url"),
        timeout=int(llm_cfg.get("timeout_seconds", 90)),
        max_retries=int(llm_cfg.get("max_retries", 2)),
    )

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
            client = DeepSeekClient(
                model=llm_cfg.get("model", "deepseek-v4-flash"),
                base_url=llm_cfg.get("base_url"),
                timeout=int(llm_cfg.get("timeout_seconds", 90)),
                max_retries=int(llm_cfg.get("max_retries", 2)),
            )
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
                "verdict": "UNKNOWN",
                "confidence": "low",
                "sufficient": False,
                "missing_evidence": ["LLM_CALL_FAILED"],
                "next_query": {"template_id": None, "parameters": {}, "reason": ""},
                "reason_summary": f"LLM call failed: {exc}",
            }
            evidence["llm_error"] = str(exc)
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
    active = list(range(len(records)))
    llm_rounds: list[dict[str, Any]] = []
    query_rounds: list[dict[str, Any]] = []
    queried_alerts: set[int] = set()
    direct_after_first_round = 0

    for record in records:
        record["llm_usage_total"] = {}
        record["runtime_breakdown"] = {"llm_seconds": 0.0, "query_count": 0}

    for iteration in range(max_iterations):
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
                client = DeepSeekClient(
                    model=llm_cfg.get("model", "deepseek-v4-flash"),
                    base_url=llm_cfg.get("base_url"),
                    timeout=int(llm_cfg.get("timeout_seconds", 90)),
                    max_retries=int(llm_cfg.get("max_retries", 2)),
                )
                decision, usage, trace = _judge_for_baseline(
                    client=client,
                    evidence=records[index],
                    allowed=allowed,
                    args=args,
                    llm_cfg=llm_cfg,
                )
            except Exception as exc:
                decision = {
                    "verdict": "UNKNOWN",
                    "confidence": "low",
                    "sufficient": False,
                    "missing_evidence": ["LLM_CALL_FAILED"],
                    "next_query": {"template_id": None, "parameters": {}, "reason": ""},
                    "reason_summary": f"LLM call failed: {exc}",
                }
                usage = {}
                trace = [{"decision": decision, "usage": usage, "baseline": args.baseline}]
                records[index]["llm_error"] = str(exc)
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
            evidence["decision"] = decision
            evidence["llm_usage_total"] = _sum_usage([evidence.get("llm_usage_total", {}), usage])
            evidence["runtime_breakdown"]["llm_seconds"] += duration
            for trace_item in trace:
                trace_item["iteration"] = iteration + 1
                evidence.setdefault("llm_trace", []).append(trace_item)

            if _decision_is_final(decision, evidence):
                finalized += 1
                if iteration == 0:
                    direct_after_first_round += 1
                continue
            if iteration + 1 >= max_iterations:
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
        "alerts": len(records),
        "workers": max(1, args.workers),
        "max_iterations": max_iterations,
        "wall_seconds": time.perf_counter() - run_started,
        "direct_after_first_round": direct_after_first_round,
        "queried_alerts": len(queried_alerts),
        "verdict_counts": verdict_counts,
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
    return _checklist_gate_satisfied(evidence)


def _checklist_gate_satisfied(evidence: dict[str, Any]) -> bool:
    """Check whether CWE-specific sufficiency checklist slots are all filled.

    Even when the LLM reports sufficient=true, the controller forces a
    supplementary query if mandatory evidence slots remain 'unknown'.
    """
    cwe = evidence.get("alert_contract", {}).get("cwe")
    profile = profile_for(cwe)
    checklist = profile.get("sufficiency_checklist", [])
    if not checklist:
        return True
    slots = evidence.get("evidence_slots", {})
    query_history = {item.get("template_id") for item in evidence.get("query_history", [])}
    for slot in checklist:
        if slots.get(slot) in {None, "unknown"}:
            return False
    return True


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
        "safe_api_usage": "yes",
        "sink_argument_origin": "yes",
    },
    "find-sql-sink-and-construction": {
        "sink_argument_origin": "yes",
        "safe_api_usage": "yes",
    },
    "find-constant-assignment-nearby": {
        "source_user_controlled": "yes",
        "sanitizer_present": "yes",
        "validator_present": "yes",
    },
    "find-xss-encoder-nearby": {
        "sanitizer_present": "yes",
    },
    "find-command-execution-arguments": {
        "sink_argument_origin": "yes",
        "sanitizer_present": "yes",
    },
    "find-path-canonical-guard": {
        "validator_present": "yes",
        "sanitizer_present": "yes",
    },
    "find-validator-or-guard": {
        "validator_present": "yes",
        "sanitizer_present": "yes",
    },
    "find-sanitizer-on-path": {
        "sanitizer_present": "yes",
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
        # Query failed; still mark slots as checked to avoid infinite loop
        for slot, value in updates.items():
            if slots.get(slot) in {None, "unknown"}:
                slots[slot] = "checked_error"


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
