# Benchmark: V-8 Scanner vs. OWASP ZAP / Nikto / Nmap Run Directly

**No results are recorded in this document yet.** The tables below are the format to fill in — every cell is either a number from a real run or the word "N/A". Do not fill these in with estimates or guesses; that defeats the point of a benchmark.

## Why benchmark against the tools V-8 Scanner itself uses?

V-8 Scanner doesn't reimplement ZAP/Nikto/Nmap's detection logic — it orchestrates them and adds deduplication, OWASP/CWE classification, confidence scoring, and prioritization on top (see `docs/AI_PIPELINE.md`). So the honest comparison isn't "does V-8 find more vulnerabilities than ZAP" (it structurally can't — every finding it has originated from one of these three tools) — it's:

1. **Does the AI Cortex layer add value** — fewer duplicate findings surfaced to an analyst, faster triage via prioritization, clearer explanations — **for the same underlying findings**?
2. **What's the orchestration overhead** — how much slower is running all three tools through V-8 Scanner vs. running them separately and manually correlating results?

## How to Run

Basic timing + findings comparison:

```bash
python scripts/benchmark/run_benchmark.py --target http://<authorized-target> --output results_$(date +%Y%m%d).json
```

With real CPU/RAM measurement (`scripts/benchmark/resource_monitor.py` samples the benchmark process and any subprocesses it spawns, e.g. nmap, on a background thread — every number is a real `psutil` sample, never estimated):

Resource usage is now measured on every run automatically — no extra flag needed. Each tool's result includes a `resources` block: `duration_seconds`, `cpu_percent_avg`, `cpu_percent_peak`, `rss_mb_avg`, `rss_mb_peak`.

With real precision/recall/false-positive/false-negative measurement, which requires YOU to supply a ground-truth file of vulnerabilities actually present in a target you control and have verified (see `scripts/benchmark/example_ground_truth.json` for the format — a deliberately-vulnerable test app like OWASP Juice Shop or DVWA is a good source, since their vulnerabilities are documented upstream):

```bash
python scripts/benchmark/run_benchmark.py --target http://localhost:3000 \
    --ground-truth scripts/benchmark/example_ground_truth.json \
    --output results_$(date +%Y%m%d).json
```

Without `--ground-truth`, no precision/recall/FP/FN numbers are computed or printed at all — there is no synthetic ground truth anywhere in this codebase, by design. See `scripts/benchmark/precision_recall.py`'s module docstring for exactly how matching works (finding-type + URL substring match — deliberately auditable, not a black box).

Run this against a target you own or are explicitly authorized to test — the same rule V-8 Scanner's active-scan mode itself enforces. Run it multiple times / against multiple targets before drawing any conclusion from a single number.

## Table 0 — Resource Usage (CPU / RAM / Duration)

| Target | Date | Tool | Duration (s) | CPU % avg | CPU % peak | RSS MB avg | RSS MB peak |
|---|---|---|---|---|---|---|---|
| _(not yet run)_ | | | | | | | |

## Table 5 — Precision / Recall / False Positives / False Negatives

Requires a real `--ground-truth` file for a target with documented, verified vulnerabilities — see above.

| Target | Ground truth source | Date | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| _(not yet run)_ | | | | | | | | |

## Table 1 — Raw Findings Count (same target, same run)

| Target | Date | Nmap (direct) ports | Nikto (direct) findings | ZAP (direct) alerts | V-8 Scanner total findings | V-8 after dedup |
|---|---|---|---|---|---|---|
| _(not yet run)_ | | | | | | |

## Table 2 — Timing

| Target | Date | Nmap alone | Nikto alone | ZAP alone | Sum of separate runs | V-8 Scanner (orchestrated) | Overhead |
|---|---|---|---|---|---|---|---|
| _(not yet run)_ | | | | | | | |

## Table 3 — Deduplication Effectiveness

| Target | Date | Raw findings (all 3 tools) | After AI Cortex dedup | Duplicates removed | % reduction |
|---|---|---|---|---|---|
| _(not yet run)_ | | | | | |

## Table 4 — Feature Comparison (not a number-based benchmark, but factual and verifiable in the code)

| Capability | Nmap alone | Nikto alone | ZAP alone | V-8 Scanner |
|---|---|---|---|---|
| Port/service discovery | Yes | No | Limited | Yes (via Nmap) |
| Web misconfiguration checks | No | Yes | Yes (passive) | Yes (via Nikto + ZAP) |
| Active exploitation-style probing | No | Limited | Yes (active scan) | Yes, opt-in only (via ZAP active scan) |
| Cross-tool deduplication | N/A | N/A | N/A | Yes |
| OWASP Top 10 / CWE mapping | No | No | Partial | Yes |
| Confidence scoring w/ cross-tool corroboration | No | No | Per-tool only | Yes |
| Unified PDF/HTML/JSON report across all 3 tools | No | No (own format only) | No (own format only) | Yes |
| Human-readable finding explanations | No | No | Partial | Yes |

This table is factual/structural (verifiable by reading the code) rather than a number to be benchmarked — filed here for completeness since it's part of the same comparison.

## Recording a Run

After running `run_benchmark.py`, transcribe the actual output numbers into the tables above — don't summarize or round in a way that loses the source data. Keep the raw JSON output files (`results_*.json`) alongside this doc for anyone who wants to verify a row.
