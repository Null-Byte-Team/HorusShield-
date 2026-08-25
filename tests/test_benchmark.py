"""Tests for scripts/benchmark/ — resource monitor and precision/recall."""

import json
import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "scripts", "benchmark"))


def test_resource_monitor_produces_real_samples():
    from resource_monitor import ResourceMonitor

    with ResourceMonitor(interval=0.05) as mon:
        # do something that takes measurable wall-clock time and some CPU
        total = 0
        for i in range(2_000_000):
            total += i
        time.sleep(0.2)

    result = mon.result()
    assert result["duration_seconds"] > 0
    assert result["sample_count"] > 0
    assert result["cpu_percent_avg"] is not None
    assert result["rss_mb_avg"] is not None
    assert result["rss_mb_avg"] > 0  # a real process always uses > 0 MB


def test_resource_monitor_handles_very_short_duration_honestly():
    from resource_monitor import ResourceMonitor

    with ResourceMonitor(interval=5.0) as mon:  # interval longer than the block
        pass

    result = mon.result()
    # too short to collect a sample at this interval -- must say so, not fabricate numbers
    if result["sample_count"] == 0:
        assert result["cpu_percent_avg"] is None
        assert "note" in result


def test_precision_recall_perfect_match():
    from precision_recall import evaluate

    ground_truth = {
        "known_findings": [
            {"finding_type": "SQL Injection", "url_contains": "/search"},
        ]
    }
    findings = [{"finding_type": "SQL Injection", "url": "http://x.com/search?q=1"}]
    result = evaluate(findings, ground_truth)
    assert result["true_positives"] == 1
    assert result["false_positives"] == 0
    assert result["false_negatives"] == 0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0


def test_precision_recall_false_positive():
    from precision_recall import evaluate

    ground_truth = {
        "known_findings": [{"finding_type": "SQL Injection", "url_contains": "/search"}]
    }
    findings = [
        {"finding_type": "SQL Injection", "url": "http://x.com/search?q=1"},
        {"finding_type": "Open Redirect", "url": "http://x.com/redirect"},  # not in ground truth
    ]
    result = evaluate(findings, ground_truth)
    assert result["true_positives"] == 1
    assert result["false_positives"] == 1
    assert result["precision"] == 0.5
    assert result["recall"] == 1.0


def test_precision_recall_false_negative():
    from precision_recall import evaluate

    ground_truth = {
        "known_findings": [
            {"finding_type": "SQL Injection", "url_contains": "/search"},
            {"finding_type": "XSS", "url_contains": "/comment"},
        ]
    }
    findings = [{"finding_type": "SQL Injection", "url": "http://x.com/search?q=1"}]
    result = evaluate(findings, ground_truth)
    assert result["true_positives"] == 1
    assert result["false_negatives"] == 1
    assert result["recall"] == 0.5
    assert len(result["unmatched_known_vulnerabilities"]) == 1


def test_precision_recall_empty_ground_truth_does_not_divide_by_zero():
    from precision_recall import evaluate

    result = evaluate([{"finding_type": "X", "url": "y"}], {"known_findings": []})
    assert result["precision"] is None
    assert result["recall"] is None
    assert "note" in result


def test_load_ground_truth_rejects_malformed_file(tmp_path):
    from precision_recall import load_ground_truth

    bad_file = tmp_path / "bad.json"
    bad_file.write_text(json.dumps({"not_known_findings": []}))
    try:
        load_ground_truth(str(bad_file))
        assert False, "should have raised ValueError"
    except ValueError:
        pass


def test_load_ground_truth_accepts_well_formed_file(tmp_path):
    from precision_recall import load_ground_truth

    good_file = tmp_path / "good.json"
    good_file.write_text(
        json.dumps(
            {
                "target": "http://localhost:3000",
                "source": "test fixture",
                "known_findings": [{"finding_type": "XSS", "url_contains": "/x"}],
            }
        )
    )
    gt = load_ground_truth(str(good_file))
    assert len(gt["known_findings"]) == 1
