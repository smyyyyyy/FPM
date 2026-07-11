# FPM Benchmark Experiment

This scaffold supports the experiment idea:

> Convert CodeQL SARIF alerts into ZeroFalse-style structured evidence, let an LLM judge whether evidence is sufficient, and if not, select parameterized CodeQL query templates to retrieve missing evidence before TP/FP/Unknown triage.

The implementation is intentionally lightweight and reproducible: Python standard library only, JSONL artifacts, and no API keys in files.

## What Is Included

- `SARIF -> structured evidence` parser
- OWASP Benchmark `expectedresults-1.2.csv` alignment
- DeepSeek-compatible JSON-output LLM client
- TP / FP / Unknown decision schema
- Operational and selective metrics
- CodeQL template manifest, renderer, and executor entry points
- Shell scripts for the planned CodeQL/Benchmark workflow

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

If this machine does not have `pip`, use the package without installation:

```bash
export PYTHONPATH="$PWD/src"
python3 -m fpm_benchmark.cli --help
```

Set your API key through the environment:

```bash
export DEEPSEEK_API_KEY="your-new-key"
```

Do not put a real key in `.env.example` or commit it.

## Tooling Check

```bash
scripts/check_env.sh
```

This project can download CodeQL CLI and BenchmarkJava locally:

```bash
scripts/bootstrap_local_toolchain.sh
scripts/bootstrap_assets.sh
export PATH="$PWD/codeql-home/codeql:$PATH"
```

You still need a working Java JDK and Maven to build OWASP Benchmark Java and create the CodeQL database.
On Ubuntu-like systems, the missing system pieces are typically:

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk maven unzip
```

## Expected Workflow

1. Prepare OWASP Benchmark Java v1.2 and CodeQL CLI.
2. Create a CodeQL database and run the default Java query suite.
3. Parse CodeQL SARIF into structured evidence.
4. Run one-shot or iterative LLM triage.
5. Evaluate against OWASP ground truth.

Example commands:

```bash
fpm-bench parse-sarif \
  --sarif data/raw/codeql-default.sarif \
  --expected BenchmarkJava/expectedresults-1.2.csv \
  --source-root BenchmarkJava \
  --out data/interim/evidence.jsonl

fpm-bench llm-triage \
  --input data/interim/evidence.jsonl \
  --out data/results/decisions.jsonl \
  --config configs/experiment.json \
  --mode one-shot \
  --view structured

fpm-bench evaluate \
  --decisions data/results/decisions.jsonl \
  --out data/results/metrics.json
```

Raw CodeQL baseline:

```bash
fpm-bench raw-codeql \
  --input data/interim/evidence.jsonl \
  --out data/results/decisions.raw_codeql.jsonl
```

SARIF-summary one-shot LLM baseline:

```bash
fpm-bench llm-triage \
  --input data/interim/evidence.jsonl \
  --out data/results/decisions.raw_sarif_llm.jsonl \
  --config configs/experiment.json \
  --mode one-shot \
  --view raw-sarif
```

One-extra-query ablation:

```bash
fpm-bench llm-triage \
  --input data/interim/evidence.jsonl \
  --out data/results/decisions.one_query.jsonl \
  --config configs/experiment.json \
  --mode iterative \
  --max-iterations 1 \
  --codeql-db benchmark-db
```

Without installation, replace `fpm-bench` with:

```bash
PYTHONPATH=src python3 -m fpm_benchmark.cli
```

For the full iterative method:

```bash
fpm-bench llm-triage \
  --input data/interim/evidence.jsonl \
  --out data/results/decisions.iterative.jsonl \
  --config configs/experiment.json \
  --mode iterative \
  --view structured \
  --max-iterations 3 \
  --codeql-db benchmark-db
```

If `--codeql-db` is omitted, the iterative mode records the requested query but cannot execute extra CodeQL evidence retrieval, so it will stop safely.

## Main Metrics

- `Precision`: kept alerts that are real vulnerabilities.
- `TP Retention`: original CodeQL true positives retained after triage.
- `FP Reduction`: original CodeQL false positives filtered out.
- `F1`: harmonic mean of Precision and TP Retention.
- `MCC`: balanced binary classification quality.
- `Unknown Rate`: abstained alerts.
- `Selective Accuracy`: accuracy on non-Unknown decisions.

See [docs/experiment_protocol.md](docs/experiment_protocol.md) for the full experimental design.
