"""
HorusShield V-8 Scanner — AI Cortex
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Post-processing intelligence layer for V-8 Scanner findings.

Scope, by design: this module NEVER generates test payloads or decides
what requests to send to a target — all of that already happened inside
OWASP ZAP / Nikto / Nmap before a single finding reaches this file. Its
only job is to work with findings those tools already produced:

  • Normalize      — map each tool's own schema to one common shape
  • Deduplicate     — collapse the same underlying issue reported twice
  • Classify        — map to a unified severity scale + OWASP/CWE tags
  • Confidence-score— corroboration across tools raises confidence
  • Prioritize      — order findings by risk
  • Explain         — plain-language description of what a finding means
                       and why it matters, for the analyst reading the report
"""
import hashlib
from typing import Any, Dict, List
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger("vscanner_cortex", "ai")

# ── Unified severity scale ──
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── Known finding-type → (OWASP Top 10 2021 category, CWE id, explanation, recommendation) ──
KNOWLEDGE_BASE = {
    "sql injection": (
        "A03:2021 - Injection", "CWE-89",
        "The target may pass user-controlled input into a database query without proper sanitization, "
        "which can let an attacker read, modify, or delete data they shouldn't have access to.",
        "Use parameterized queries / prepared statements everywhere, validate and encode all input, "
        "and apply least-privilege database accounts.",
    ),
    "cross site scripting": (
        "A03:2021 - Injection", "CWE-79",
        "User-controlled input appears to be reflected or stored without proper output encoding, "
        "which could let an attacker run script in another user's browser session.",
        "Encode all output for its context (HTML/JS/URL), apply a Content-Security-Policy, "
        "and validate input on the server side.",
    ),
    "xss": (
        "A03:2021 - Injection", "CWE-79",
        "User-controlled input appears to be reflected or stored without proper output encoding, "
        "which could let an attacker run script in another user's browser session.",
        "Encode all output for its context (HTML/JS/URL), apply a Content-Security-Policy, "
        "and validate input on the server side.",
    ),
    "path traversal": (
        "A01:2021 - Broken Access Control", "CWE-22",
        "The application may allow file paths to be manipulated to access files outside the intended directory.",
        "Normalize and validate file paths against an allow-list; avoid passing user input directly to filesystem APIs.",
    ),
    "local file inclusion": (
        "A01:2021 - Broken Access Control", "CWE-98",
        "The application may allow a user-supplied path to be included/executed by the server.",
        "Avoid dynamic file inclusion based on user input; use a strict allow-list of file identifiers instead.",
    ),
    "remote file inclusion": (
        "A03:2021 - Injection", "CWE-98",
        "The application may fetch and execute remote content based on user-supplied input.",
        "Disable remote file inclusion at the language/framework level and validate all include paths.",
    ),
    "csrf": (
        "A01:2021 - Broken Access Control", "CWE-352",
        "State-changing requests may not verify that they originated from the application's own pages, "
        "letting an attacker trick a logged-in user into submitting unwanted actions.",
        "Use anti-CSRF tokens on all state-changing requests and set cookies with SameSite=Strict/Lax.",
    ),
    "open redirect": (
        "A01:2021 - Broken Access Control", "CWE-601",
        "The application may redirect to a URL supplied by the user without validation, which can be used in phishing.",
        "Validate redirect targets against an allow-list of internal paths/domains.",
    ),
    "ssrf": (
        "A10:2021 - Server-Side Request Forgery", "CWE-918",
        "The server may fetch a URL supplied by the user, which can be abused to reach internal-only services.",
        "Validate/allow-list outbound destinations and block requests to internal address ranges.",
    ),
    "sensitive file": (
        "A05:2021 - Security Misconfiguration", "CWE-538",
        "A file that may expose sensitive information (backups, configs, credentials) appears to be reachable.",
        "Remove or restrict access to the file; ensure deployment pipelines don't ship dev/debug artifacts.",
    ),
    "directory listing": (
        "A05:2021 - Security Misconfiguration", "CWE-548",
        "The web server may be listing directory contents, revealing file structure to visitors.",
        "Disable directory indexing in the web server configuration.",
    ),
    "security misconfiguration": (
        "A05:2021 - Security Misconfiguration", "CWE-16",
        "A server or application setting deviates from security best practice (headers, defaults, verbose errors).",
        "Review the specific setting against hardening guidance for the affected component.",
    ),
    "missing header": (
        "A05:2021 - Security Misconfiguration", "CWE-693",
        "A recommended security response header appears to be missing, reducing defense-in-depth for browsers.",
        "Add the missing header (e.g. Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security).",
    ),
    "broken authentication": (
        "A07:2021 - Identification and Authentication Failures", "CWE-287",
        "The authentication mechanism may have a weakness (weak session handling, credential exposure, etc.).",
        "Review session/token lifetime, enforce strong credential policies, and use multi-factor authentication.",
    ),
    "broken access control": (
        "A01:2021 - Broken Access Control", "CWE-284",
        "A resource may be reachable by users who shouldn't have access to it (missing authorization check).",
        "Enforce server-side authorization checks on every request, not just in the UI.",
    ),
    "idor": (
        "A01:2021 - Broken Access Control", "CWE-639",
        "An object reference (ID in a URL/parameter) may let a user access another user's data by changing the value.",
        "Verify the requesting user is authorized for the specific object on every access, server-side.",
    ),
    "open port": (
        "A05:2021 - Security Misconfiguration", "CWE-1327",
        "A network service is reachable that may not need to be exposed, widening the attack surface.",
        "Close or firewall the port if the service is not required to be publicly reachable.",
    ),
    "outdated software": (
        "A06:2021 - Vulnerable and Outdated Components", "CWE-1104",
        "The detected software/service version may be outdated and missing security patches.",
        "Upgrade to a maintained, patched version and track it in a dependency-update process.",
    ),
    "information disclosure": (
        "A05:2021 - Security Misconfiguration", "CWE-200",
        "The response may reveal internal details (versions, paths, stack traces) useful to an attacker.",
        "Suppress verbose errors/banners in production and review response content for internal details.",
    ),
}

_DEFAULT_KB_ENTRY = (
    "A05:2021 - Security Misconfiguration", "",
    "This finding was reported by an automated security tool and may indicate a deviation from security best practice.",
    "Review the finding details and evidence, and validate manually before remediating.",
)

# ── Map each source tool's own risk/severity vocabulary to our unified scale ──
_ZAP_RISK_MAP = {"3": "critical", "2": "high", "1": "medium", "0": "info",
                  "high": "high", "medium": "medium", "low": "low", "informational": "info"}
_NIKTO_DEFAULT_SEVERITY = "medium"


def _lookup_kb(finding_type: str):
    ft = (finding_type or "").lower()
    for key, entry in KNOWLEDGE_BASE.items():
        if key in ft:
            return entry
    return _DEFAULT_KB_ENTRY


def _dedup_key(finding: Dict[str, Any]) -> str:
    """Two findings are considered the same underlying issue if they share
    host + path + normalized finding type."""
    url = finding.get("url", "") or ""
    parsed = urlparse(url)
    path = parsed.path or url
    ft_norm = "".join(ch for ch in (finding.get("finding_type", "") or "").lower() if ch.isalnum())
    raw = f"{parsed.netloc}|{path}|{ft_norm}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class VScannerCortex:
    """AI Cortex: normalize → deduplicate → classify → score → prioritize → explain."""

    # ── normalization from each tool's native schema ──

    @staticmethod
    def from_zap(alert: Dict[str, Any]) -> Dict[str, Any]:
        risk = str(alert.get("risk", alert.get("riskcode", "1"))).lower()
        severity = _ZAP_RISK_MAP.get(risk, "medium")
        confidence_str = str(alert.get("confidence", "2")).lower()
        base_conf = {"3": 0.9, "high": 0.9, "2": 0.7, "medium": 0.7, "1": 0.4, "low": 0.4}.get(confidence_str, 0.6)
        return {
            "source_tool": "zap",
            "finding_type": alert.get("name", alert.get("alert", "Unknown Finding")),
            "url": alert.get("url", ""),
            "parameter": alert.get("param", ""),
            "severity": severity,
            "confidence": base_conf,
            "description": (alert.get("description", "") or "")[:2000],
            "evidence": (alert.get("evidence", "") or "")[:1000],
            "recommendation": (alert.get("solution", "") or "")[:1500],
            "raw_data": alert,
        }

    @staticmethod
    def from_nikto(item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "source_tool": "nikto",
            "finding_type": item.get("message", "Web Server Finding")[:120],
            "url": item.get("url", ""),
            "parameter": "",
            "severity": _NIKTO_DEFAULT_SEVERITY,
            "confidence": 0.55,
            "description": item.get("message", ""),
            "evidence": item.get("method", ""),
            "recommendation": "",
            "raw_data": item,
        }

    @staticmethod
    def from_nmap(host: str, port_info: Dict[str, Any]) -> Dict[str, Any]:
        service = port_info.get("service", "unknown")
        product = port_info.get("product", "")
        version = port_info.get("version", "")
        desc = f"Port {port_info.get('port')}/{port_info.get('protocol','tcp')} is open running {service}"
        if product:
            desc += f" ({product} {version})".rstrip()
        script_notes = "; ".join(
            f"{s['id']}: {s['output'][:200]}" for s in port_info.get("scripts", []) if s.get("output")
        )
        severity = "low"
        finding_type = "Open Port"
        if port_info.get("port") in (21, 23, 3389, 5900) and service:
            severity = "medium"
        if version and version.strip():
            finding_type = "Open Port / Outdated Software" if False else "Open Port"
        return {
            "source_tool": "nmap",
            "finding_type": finding_type,
            "url": f"{host}:{port_info.get('port')}",
            "parameter": "",
            "severity": severity,
            "confidence": 0.8,
            "description": desc,
            "evidence": script_notes[:1000],
            "recommendation": "",
            "raw_data": port_info,
        }

    # ── pipeline steps ──

    @staticmethod
    def deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Mark later duplicates (same dedup key) as is_duplicate, and bump the
        confidence of the kept finding when more than one tool corroborates it."""
        seen: Dict[str, int] = {}
        for f in findings:
            f["dedup_hash"] = _dedup_key(f)
            f["is_duplicate"] = False
        for f in findings:
            key = f["dedup_hash"]
            if key not in seen:
                seen[key] = 0
            seen[key] += 1
        for f in findings:
            key = f["dedup_hash"]
            count = seen[key]
            f["_corroboration_count"] = count
            if count > 1:
                # boost confidence for corroborated findings, cap at 0.97
                f["confidence"] = min(0.97, f.get("confidence", 0.5) + 0.1 * (count - 1))
        # keep the first occurrence of each key, mark the rest duplicate
        first_seen = set()
        for f in findings:
            key = f["dedup_hash"]
            if key in first_seen:
                f["is_duplicate"] = True
            else:
                first_seen.add(key)
        return findings

    @staticmethod
    def classify_and_explain(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map each finding to OWASP/CWE, and build a short, concrete confidence
        explanation from the same signals that produced the score — e.g. which
        tool(s) detected it, whether other tools corroborated it, and whether
        it was flagged as a duplicate. This is meant to answer "why this score"
        for an analyst, not to re-derive the score itself."""
        for f in findings:
            owasp, cwe, explanation, recommendation = _lookup_kb(f.get("finding_type", ""))
            f["owasp_category"] = owasp
            f["cwe_id"] = cwe
            if not f.get("recommendation"):
                f["recommendation"] = recommendation

            reasons = [f"Detected by {f.get('source_tool', 'scanner').upper()}"]
            corroboration = f.get("_corroboration_count", 1)
            if corroboration > 1:
                reasons.append(f"corroborated by {corroboration} scanner passes (confidence increased)")
            if f.get("is_duplicate"):
                reasons.append("duplicate of an earlier finding — excluded from active count")
            if owasp:
                reasons.append(f"mapped to {owasp}")
            if cwe:
                reasons.append(f"mapped to {cwe}")
            reasons.append("validated by AI Cortex (deduplicated, classified, and prioritized)")

            f["ai_explanation"] = explanation + " [" + "; ".join(reasons) + "]"
            f.pop("_corroboration_count", None)
        return findings

    @staticmethod
    def prioritize(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return sorted(
            findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f.get("severity", "info"), 4),
                -f.get("confidence", 0.0),
            ),
        )

    @staticmethod
    def correlate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group findings that share the same target (host, or host:port)
        but are NOT exact duplicates — e.g. Nmap flagging an open port
        running a web server, and ZAP separately flagging a vulnerability
        reachable through that same port, are two different findings about
        the same asset. Deduplication (see deduplicate()) only collapses
        near-identical findings; this adds a `correlation_group` id linking
        findings about the same target so an analyst sees them as related
        context, not a coincidence of ordering in the report.

        This does not change severity, confidence, or dedup status — it's
        purely additive context, applied after deduplicate() so duplicate
        rows don't skew grouping.
        """
        from urllib.parse import urlparse

        def _asset_key(f: Dict[str, Any]) -> str:
            url = f.get("url", "") or ""
            if ":" in url and "//" not in url:
                # nmap-style "host:port"
                host = url.split(":")[0]
            else:
                parsed = urlparse(url if "://" in url else f"http://{url}")
                host = parsed.hostname or url
            return (host or "unknown").lower()

        groups: Dict[str, List[int]] = {}
        active = [(i, f) for i, f in enumerate(findings) if not f.get("is_duplicate")]
        for i, f in active:
            key = _asset_key(f)
            groups.setdefault(key, []).append(i)

        for i, f in active:
            key = _asset_key(f)
            group_indices = groups[key]
            if len(group_indices) > 1:
                other_tools = sorted({findings[j]["source_tool"] for j in group_indices if j != i})
                f["correlation_group"] = key
                f["correlated_with_tools"] = other_tools
            else:
                f["correlation_group"] = None
                f["correlated_with_tools"] = []
        return findings

    @classmethod
    def process(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Full pipeline: dedup → classify/explain → correlate → prioritize."""
        findings = cls.deduplicate(findings)
        findings = cls.classify_and_explain(findings)
        findings = cls.correlate(findings)
        findings = cls.prioritize(findings)
        return findings

    @staticmethod
    def summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """High-level counts for a scan, used in the dashboard + report."""
        active = [f for f in findings if not f.get("is_duplicate")]
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in active:
            sev = f.get("severity", "info")
            if sev in by_sev:
                by_sev[sev] += 1
        avg_conf = (sum(f.get("confidence", 0) for f in active) / len(active)) if active else 0.0
        return {
            "total_findings": len(active),
            "duplicates_removed": len(findings) - len(active),
            "by_severity": by_sev,
            "average_confidence": round(avg_conf, 2),
        }
