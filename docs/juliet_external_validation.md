# Juliet Java 1.3 external validation

## Frozen inputs

- Dataset: NIST SARD Juliet Test Suite for Java 1.3.
- Official archive SHA-256:
  `d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60`.
- CodeQL CLI: 2.25.5.
- Query suite: `codeql/java-queries:codeql-suites/java-code-scanning.qls`.
- FPM method: use the frozen v1.4 prompt, gate, and evidence templates without
  tuning them on Juliet results.

The Java source must be compiled with the jars shipped in Juliet. A
`build-mode=none` smoke test completed but had only 47% resolved call targets,
66% known expression types, and missed all CWE-614 alerts. It is not suitable
for the experiment.

Run the static preparation with:

```bash
bash scripts/prepare_juliet_static.sh
```

Set `FORCE=1` only when the frozen database and SARIF should be regenerated.

## CWE mapping

| Research category | Juliet directories | CodeQL rule |
| --- | --- | --- |
| CWE-022 | CWE-23, CWE-36 | `java/path-injection` |
| CWE-078 | CWE-78 | `java/command-line-injection` |
| CWE-079 | CWE-80, CWE-81, CWE-83 | `java/xss` |
| CWE-089 | CWE-89 | `java/sql-injection` |
| CWE-090 | CWE-90 | `java/ldap-injection` |
| CWE-327 | CWE-327 | `java/weak-cryptographic-algorithm` |
| CWE-330 | CWE-336, CWE-338 | `java/predictable-seed` |
| CWE-614 | CWE-614 | `java/insecure-cookie` |
| CWE-643 | CWE-643 | `java/xml/xpath-injection` |

CWE-501 is absent from Juliet Java 1.3. The CWE-330 mapping is explicit:
Juliet removed its old exact CWE-330 cases, while the relevant descendants are
CWE-336 and CWE-338; CodeQL tags its predictable-seed rule as CWE-335. The
adapter maps only that rule in those directories to the research category
CWE-330.

## Alert-level ground truth

The manifest identifies flaw locations but does not directly label every
CodeQL alert. `CallableLocations.ql` exports each callable's file, source range,
declaring class, and method name. A target-rule SARIF alert is labeled as:

- TP when its primary location is in a `bad*` callable or a helper class ending
  in `_bad`.
- FP when its primary location is in a `good*` callable or a helper class ending
  in `_goodG2B`/`_goodB2G`.
- UNKNOWN if there is no unique enclosing callable or the signals conflict.

Incidental alerts for other rules or support code are excluded. Multi-file
testcase families remain grouped for clustered analysis.

## Current static inventory

The 13 mapped Juliet directories contain 5,874 testcases. CodeQL produced 4,135
alerts, of which 4,012 match the registered target rule and directory pairs:

| CWE | TP | FP | Total |
| --- | ---: | ---: | ---: |
| CWE-022 | 1,332 | 36 | 1,368 |
| CWE-078 | 222 | 6 | 228 |
| CWE-079 | 666 | 18 | 684 |
| CWE-089 | 1,110 | 30 | 1,140 |
| CWE-090 | 222 | 6 | 228 |
| CWE-327 | 102 | 0 | 102 |
| CWE-330 | 17 | 0 | 17 |
| CWE-614 | 17 | 0 | 17 |
| CWE-643 | 222 | 6 | 228 |
| **Total** | **3,910** | **102** | **4,012** |

Raw CodeQL precision is 97.46%. The 102 FPs are concentrated in Juliet's
shared-state/multi-call variants, where CodeQL joins a bad source path to a
`goodG2B` sink. This is a useful external failure mode, but it is narrower and
more imbalanced than OWASP Benchmark.

## Leakage control

Juliet embeds labels in method and file names such as `bad()`, `goodG2B()`, and
`_81_bad.java`. Removing the `ground_truth` object alone is insufficient. The
LLM projection deterministically aliases those tokens per alert and strips
comments before every round, including supplemental query evidence. Query
execution uses controller-owned original locations, so an anonymized path
returned by the LLM cannot break or redirect a query.

The current full-corpus audit found zero occurrences of ground-truth fields,
Juliet good/bad naming signals, `FIX`, or `POTENTIAL FLAW` in all 4,012
query-centered LLM views.

## Experiment order

1. Run a no-API static preparation and leakage audit.
2. Run a small infrastructure pilot containing all six CWE-078 FPs plus matched
   TPs. Use it only to verify API reliability and artifact generation.
3. Run the frozen method on all 4,012 alerts. All 3,910 TPs are needed for a
   defensible TP-retention estimate; an FP-only sample cannot establish safety.
4. Report TP Retention, FP Reduction, Unknown Rate, post-filter precision, MCC,
   runtime, token use, and cost. Include Wilson intervals and testcase-family
   clustered bootstrap intervals because alerts within a Juliet family are not
   independent.
5. Compare the same frozen baselines and model settings used on OWASP. Do not
   change templates or the gate after seeing Juliet outcomes. If Juliet informs
   a method change, call it a development set and reserve another untouched
   corpus or real-world labeled sample for final external evaluation.
