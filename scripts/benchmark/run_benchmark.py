#!/usr/bin/env python3
"""
V-8 Scanner Benchmark Harness
==============================
Runs V-8 Scanner (which itself orchestrates ZAP + Nikto + Nmap) against a
target, and separately times/counts the same three tools run directly and
independently, so the two can be compared honestly. Also measures real
CPU/RAM usage and, if a ground-truth file is supplied, real precision/
recall/false-positive/false-negative counts.

This script produces NO fabricated numbers anywhere. If a tool isn't
installed/reachable, its row is marked "not run". If no --ground-truth
file is given, no precision/recall numbers are printed at all — not
zeros, not estimates. Run this yourself against a target you're
authorized to test; the comparison tables in docs/BENCHMARK_RESULTS.md
stay empty until you do.

Usage:
    python scripts/benchmark/run_benchmark.py --target http://your-authorized-target.test
    python scripts/benchmark/run_benchmark.py --target http://localhost:3000 \
        --ground-truth scripts/benchmark/example_ground_truth.json

Requires: HorusShield backend importable (run from repo root with
backend/ on PYTHONPATH), and whichever of nmap/nikto/zap you want compared
actually installed/running.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
sys.path.insert(0, BACKEND_DIR)
sys.path.insert(0, SCRIPT_DIR)

from resource_monitor import ResourceMonitor  # noqa: E402


def _timed(label, fn):
    print(f"  Running: {label} ...")
    start = time.time()
    try:
        with ResourceMonitor(interval=0.5) as mon:
            result = fn()
        elapsed = time.time() - start
        return {
            "label": label,
            "ran": True,
            "seconds": round(elapsed, 2),
            "result": result,
            "resources": mon.result(),
            "error": None,
        }
    except Exception as e:
        elapsed = time.time() - start
        return {
            "label": label,
            "ran": False,
            "seconds": round(elapsed, 2),
            "result": None,
            "resources": None,
            "error": str(e),
        }


def run_nmap_direct(target_host):
    from vscanner.nmap_runner import NmapRunner

    runner = NmapRunner()
    if not runner.is_available():
        raise RuntimeError("nmap binary not found on PATH")
    res = runner.scan(target_host)
    return {"success": res["success"], "ports_found": len(res.get("ports", []))}


def run_nikto_direct(target_url):
    from vscanner.nikto_runner import NiktoRunner

    runner = NiktoRunner()
    if not runner.is_available():
        raise RuntimeError("nikto binary not found on PATH")
    res = runner.scan(target_url)
    return {"success": res["success"], "findings_found": len(res.get("findings", []))}


def run_zap_direct(target_url):
    from vscanner.zap_client import ZAPClient

    client = ZAPClient()
    if not client.is_available():
        raise RuntimeError("ZAP daemon not reachable")
    client.new_session()
    spider_res = client.spider(target_url)
    client.passive_scan_wait()
    alerts = client.get_alerts(target_url)
    return {
        "success": spider_res.get("success", False),
        "urls_found": spider_res.get("urls_found", 0),
        "alerts_found": len(alerts),
    }


def run_v8_scanner(target_url, tools):
    """Runs V-8 Scanner's orchestrator directly (not via the Flask API), so
    the benchmark doesn't require a running server. Returns the raw
    findings list too, so --ground-truth evaluation can run against them."""
    from database.db_manager import db
    from utils.helpers import generate_session_id
    from vscanner.orchestrator import VScannerManager

    manager = VScannerManager(socketio=None)
    scan_id = generate_session_id()
    db.add_vscan(scan_id, target_url, tools, active_scan=False, requested_by="benchmark")
    manager._run(scan_id, target_url, tools, active_scan=False)  # synchronous, not threaded
    scan = db.get_vscan(scan_id)
    findings = db.get_vscan_findings(scan_id)
    return {
        "status": scan["status"],
        "findings_count": len(findings),
        "by_severity": {
            sev: sum(1 for f in findings if f["severity"] == sev)
            for sev in ("critical", "high", "medium", "low", "info")
        },
        "_findings": findings,  # consumed by --ground-truth evaluation, stripped before printing
    }


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark V-8 Scanner against ZAP/Nikto/Nmap run directly"
    )
    parser.add_argument("--target", required=True, help="Target URL you are authorized to test")
    parser.add_argument("--tools", default="nmap,zap,nikto", help="Comma-separated tool list")
    parser.add_argument(
        "--ground-truth",
        default=None,
        help="Path to a ground-truth JSON file (see precision_recall.py docstring for format) "
        "listing known vulnerabilities in the target, for real precision/recall/FP/FN "
        "measurement. Without this flag, no precision/recall numbers are computed at all.",
    )
    parser.add_argument(
        "--output", default=None, help="Path to write JSON results (default: stdout only)"
    )
    args = parser.parse_args()

    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    host = args.target.split("://")[-1].split("/")[0].split(":")[0]

    print(f"Benchmarking against: {args.target}")
    print(f"Tools: {tools}")
    print("=" * 60)

    results = {"target": args.target, "timestamp": datetime.now().isoformat(), "runs": []}

    if "nmap" in tools:
        results["runs"].append(_timed("Nmap (direct)", lambda: run_nmap_direct(host)))
    if "nikto" in tools:
        results["runs"].append(_timed("Nikto (direct)", lambda: run_nikto_direct(args.target)))
    if "zap" in tools:
        results["runs"].append(_timed("OWASP ZAP (direct)", lambda: run_zap_direct(args.target)))

    v8_result = _timed("V-8 Scanner (orchestrated)", lambda: run_v8_scanner(args.target, tools))
    results["runs"].append(v8_result)

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    for r in results["runs"]:
        status = "OK" if r["ran"] else f"FAILED ({r['error']})"
        print(f"  {r['label']:32s} {r['seconds']:>7.2f}s  {status}")
        if r["ran"]:
            printable = {k: v for k, v in r["result"].items() if k != "_findings"}
            print(f"      result:    {json.dumps(printable)}")
            if r["resources"]:
                print(f"      resources: {json.dumps(r['resources'])}")

    # ── Precision / recall, only if real ground truth was supplied ──
    if args.ground_truth:
        from precision_recall import evaluate, load_ground_truth

        print("\n" + "=" * 60)
        print("PRECISION / RECALL (against supplied ground truth)")
        print("=" * 60)
        try:
            gt = load_ground_truth(args.ground_truth)
            v8_findings = (v8_result.get("result") or {}).get("_findings", [])
            pr = evaluate(v8_findings, gt)
            results["precision_recall"] = pr
            print(f"  Ground truth source: {gt.get('source', args.ground_truth)}")
            print(f"  True positives:  {pr['true_positives']}")
            print(f"  False positives: {pr['false_positives']}")
            print(f"  False negatives: {pr['false_negatives']}")
            print(f"  Precision: {pr['precision']}")
            print(f"  Recall:    {pr['recall']}")
            print(f"  F1:        {pr['f1']}")
        except Exception as e:
            print(f"  Could not evaluate against ground truth: {e}")

    # strip internal _findings before writing/printing the final JSON —
    # it's raw scan data, not a benchmark metric
    for r in results["runs"]:
        if r.get("result") and "_findings" in r["result"]:
            del r["result"]["_findings"]

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nFull results written to {args.output}")

    print("\nNOTE: these numbers are specific to this one run, this one target, and this")
    print("environment's tool versions/hardware. Don't generalize from a single run — see")
    print("docs/BENCHMARK_RESULTS.md for how to record multiple runs properly.")


if __name__ == "__main__":
    main()
