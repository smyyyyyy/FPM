# Aligned OWASP Run 2026-07-10

This run aligns the implementation with the team design:

- B0 Raw CodeQL
- B1 Direct LLM
- B2 LLM4SA-style
- B3 ZeroFalse-style
- B4 Conservative Score
- B5 Self-Consistency
- Ours Query-Centered Evidence

## Dataset

The current runnable OWASP source is the normalized OWASP Benchmark Java pilot set imported from:

```text
/home/smy/paper2/runs/qgfpm_full/normalized_alerts.jsonl
```

Converted evidence:

```text
data/interim/evidence.normalized.jsonl
```

Snapshot:

```text
alerts: 300
TP: 160
FP: 140
CWE coverage in pilot: CWE-022, CWE-078, CWE-079, CWE-089
```

The default CodeQL SARIF route is still blocked by local absence of the `codeql/java-queries` query pack. CodeQL CLI itself is available at:

```text
/home/smy/paper2/tools/codeql/codeql
```

## Artifacts

First-50 baseline outputs:

```text
data/results/aligned_owasp_first50.b1_direct_llm.jsonl
data/results/aligned_owasp_first50.b2_llm4sa_style.jsonl
data/results/aligned_owasp_first50.b3_zerofalse_style.jsonl
data/results/aligned_owasp_first50.b4_conservative_score.jsonl
```

First-20 B5:

```text
data/results/aligned_owasp_first20.b5_self_consistency.jsonl
```

First-10 Ours:

```text
data/results/aligned_owasp_first10.ours_query_centered.jsonl
```

## First-50 Results

| Method | Count | Precision | TP Retention | FP Reduction | F1 | MCC | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| B0 Raw CodeQL | 50 | 0.5800 | 1.0000 | 0.0000 | 0.7342 | n/a | 0.0000 |
| B1 Direct LLM | 50 | 0.5556 | 0.8621 | 0.0476 | 0.6757 | -0.1486 | 0.4000 |
| B2 LLM4SA-style | 50 | 0.5455 | 0.8276 | 0.0476 | 0.6575 | -0.1895 | 0.3800 |
| B3 ZeroFalse-style | 50 | 0.5333 | 0.8276 | 0.0000 | 0.6486 | -0.2837 | 0.5400 |
| B4 Conservative Score | 50 | 0.5455 | 0.8276 | 0.0476 | 0.6575 | -0.1895 | 0.2200 |

## First-20 Results

| Method | Count | Precision | TP Retention | FP Reduction | F1 | MCC | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| B0 Raw CodeQL | 20 | 0.6000 | 1.0000 | 0.0000 | 0.7500 | n/a | 0.0000 |
| B1 Direct LLM | 20 | 0.5789 | 0.9167 | 0.0000 | 0.7097 | -0.1873 | 0.5000 |
| B2 LLM4SA-style | 20 | 0.5556 | 0.8333 | 0.0000 | 0.6667 | -0.2722 | 0.4000 |
| B3 ZeroFalse-style | 20 | 0.5556 | 0.8333 | 0.0000 | 0.6667 | -0.2722 | 0.5000 |
| B4 Conservative Score | 20 | 0.6111 | 0.9167 | 0.1250 | 0.7333 | 0.0680 | 0.3000 |
| B5 Self-Consistency | 20 | 0.5789 | 0.9167 | 0.0000 | 0.7097 | -0.1873 | 0.4500 |

## First-10 Results

| Method | Count | Precision | TP Retention | FP Reduction | F1 | MCC | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| B0 Raw CodeQL | 10 | 0.6000 | 1.0000 | 0.0000 | 0.7500 | n/a | 0.0000 |
| B1 Direct LLM | 10 | 0.6000 | 1.0000 | 0.0000 | 0.7500 | n/a | 0.4000 |
| B2 LLM4SA-style | 10 | 0.5556 | 0.8333 | 0.0000 | 0.6667 | -0.2722 | 0.4000 |
| B3 ZeroFalse-style | 10 | 0.5556 | 0.8333 | 0.0000 | 0.6667 | -0.2722 | 0.6000 |
| B4 Conservative Score | 10 | 0.6000 | 1.0000 | 0.0000 | 0.7500 | n/a | 0.3000 |
| Ours Query-Centered | 10 | 0.6000 | 1.0000 | 0.0000 | 0.7500 | n/a | 0.6000 |

## Preliminary Takeaways

1. B1-B4 reduce a small number of false positives on first-50, but they also suppress true positives, so they do not satisfy the 100% TP Retention constraint.
2. B4 improves FP Reduction on first-20, but still loses TP Retention.
3. B5 is more conservative than B4, but in this first-20 sample it did not improve FP Reduction.
4. Ours has the intended conservative behavior on first-10: TP Retention remains 100%, but Unknown is high and FP Reduction is still 0 on this small sample.
5. The results support the team's RQ framing: prompt-only and flow-trace-only baselines are not enough; the next iteration should improve query templates and FP-specific evidence acquisition.
