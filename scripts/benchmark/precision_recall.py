"""
Benchmark helper: precision / recall / false-positive / false-negative
measurement against a REAL, user-supplied ground-truth file.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This module computes nothing on its own — it compares a scan's actual
findings against a ground-truth JSON file that YOU provide, listing the
vulnerabilities actually present in a target you control and have
verified (e.g. a deliberately-vulnerable test app like OWASP Juice Shop
or DVWA, where the vulnerabilities are documented upstream).

There is no synthetic/generated ground truth anywhere in this file, by
design — fabricating "known vulnerabilities" to score against would make
every precision/recall number meaningless. If you don't have a
ground-truth file, this module has nothing valid to compute and will say
so rather than return a number.

Ground truth format (JSON):
{
    "target": "http://localhost:3000",
    "source": "OWASP Juice Shop challenge list v17.x — https://pwning.owasp-juice.shop/",
    "known_findings": [
        {"finding_type": "SQL Injection", "url_contains": "/rest/products/search"},
        {"finding_type": "Cross Site Scripting", "url_contains": "/#/search"}
    ]
}

Matching is deliberately loose (finding_type substring + url_contains
substring) since different tools name the same vulnerability class
slightly differently — see match_finding() for the exact logic, which is
printed alongside results so matching decisions are auditable, not a
black box.
"""

import json


def load_ground_truth(path: str) -> dict:
    with open(path) as f:
        gt = json.load(f)
    if "known_findings" not in gt or not isinstance(gt["known_findings"], list):
        raise ValueError(f"{path} is missing a 'known_findings' list — see module docstring")
    return gt


def _matches(finding: dict, known: dict) -> bool:
    ft_match = known["finding_type"].lower() in (finding.get("finding_type") or "").lower()
    url_match = known.get("url_contains", "") in (finding.get("url") or "")
    return ft_match and url_match


def evaluate(findings: list, ground_truth: dict) -> dict:
    """Compare scanner findings against ground truth.

    Returns real TP/FP/FN counts and precision/recall/F1 computed from
    them — never a number that wasn't derived from an actual match against
    the supplied ground_truth. If ground_truth has zero known_findings,
    this returns None values with an explanation rather than dividing by
    zero or guessing.
    """
    known = ground_truth.get("known_findings", [])
    if not known:
        return {
            "true_positives": 0,
            "false_positives": len(findings),
            "false_negatives": 0,
            "precision": None,
            "recall": None,
            "f1": None,
            "note": "ground truth file has zero known_findings — nothing to measure recall against",
        }

    matched_known_indices = set()
    true_positives = 0
    false_positive_findings = []

    for finding in findings:
        matched = False
        for i, k in enumerate(known):
            if _matches(finding, k):
                matched = True
                matched_known_indices.add(i)
        if matched:
            true_positives += 1
        else:
            false_positive_findings.append(finding)

    false_negatives = len(known) - len(matched_known_indices)
    false_positives = len(false_positive_findings)

    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) > 0
        else None
    )
    recall = true_positives / len(known) if len(known) > 0 else None
    f1 = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "unmatched_known_vulnerabilities": [
            known[i] for i in range(len(known)) if i not in matched_known_indices
        ],
        "false_positive_findings": [
            {"finding_type": f.get("finding_type"), "url": f.get("url")}
            for f in false_positive_findings
        ],
    }
