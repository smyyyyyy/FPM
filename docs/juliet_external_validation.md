# Juliet Java 1.3 external validation

## Frozen inputs

- Dataset: NIST SARD Juliet Test Suite for Java 1.3.
- Official archive SHA-256:
  `d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60`.
- CodeQL CLI: 2.25.5.
- Query suite: `codeql/java-queries:codeql-suites/java-code-scanning.qls`.
- Initial FPM method: frozen v1.4 prompt, gate, and evidence templates. The
  first Juliet pilot exposed a shared-field context failure and was therefore
  used as development feedback. Results from the revised method are not an
  untouched external-validation result.

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

## Shared-field context development result

The frozen method classified all 204 balanced-pilot alerts as TP: TP Retention
was 100%, but FP Reduction was 0%. CodeQL's SARIF traces crossed a mutable
static field and combined a source writer with a sink from another entry-call
context. The original gate treated a complete-looking source-to-sink trace as
sufficient and did not request the evidence needed to disambiguate callers.

The development revision adds a dataset-independent, narrow trigger for a
cross-file trace containing an explicit mutable static-field declaration. It
then executes `find-static-field-call-context`, which aligns each field write
with a caller that directly invokes the callable containing the alert sink.
The query reports only the relation, source lines, assigned expression, and
compile-time-constant status; it does not expose callable names. The controller
rejects a TP conclusion for a constant-only caller and rejects an FP conclusion
when the aligned caller contains a non-constant write.

On the full 204-alert label-blind development pilot:

| Metric | Result |
| --- | ---: |
| TP Retention | 100.00% |
| FP Reduction | 100.00% |
| Post-filter Precision | 100.00% |
| Unknown Rate | 0.98% (2/204) |
| MCC on decided alerts | 1.0 |
| Infrastructure failures | 0 |

The final decisions were 100 TP, 102 FP, and 2 UNKNOWN; both UNKNOWN alerts
were ground-truth TPs and therefore remained operationally retained. The
initial context query covered all 204 alerts using one compiled batch (180
unique file/line requests) in 23.2 seconds. The complete cold run took 566.6
seconds with 16 LLM workers.

The trigger matches exactly 204 of the 4,012 Juliet alerts (102 TP and 102 FP).
It matches zero alerts in the frozen 1,974-alert OWASP corpus, and replaying the
new gate over existing OWASP decisions leaves all 1,920 decided records'
finality unchanged. This is a static non-regression check, not a replacement
for a fresh OWASP model run.

Because this revision was designed after inspecting the Juliet failure, the
204-alert result is a development result. A paper must evaluate this frozen
revision on another untouched corpus or real-world labeled sample before
claiming cross-dataset generalization.

## Experiment order

1. Run a no-API static preparation and leakage audit.
2. Run the 204-alert balanced pilot containing all 102 FPs plus one TP from the
   same CWE and testcase family for every FP. Use it to verify API reliability,
   query execution, and whether the frozen method can recognize Juliet's FP
   pattern. Its precision is not a population estimate.
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

Run the OpenCode Go pilot with:

```bash
export DEEPSEEK_API_KEY='...'
WORKERS=8 MODEL=deepseek-v4-flash bash scripts/run_juliet_go.sh
```

After the pilot has zero infrastructure failures, run the full external test:

```bash
SCOPE=full WORKERS=8 MODEL=deepseek-v4-flash bash scripts/run_juliet_go.sh
```
