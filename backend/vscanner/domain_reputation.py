"""
HorusShield V-8 Scanner — Domain Reputation & Caching System
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Provides:
  1. Fast Whitelist Verification: Instantly verifies known safe, high-reputation
     global platforms (e.g. YouTube, Google, Microsoft, Apple, Cloudflare, etc.)
     without freezing the system with heavy raw socket port sweeps.
  2. Fast Blacklist Detection: Instantly flags known malicious domains.
  3. Non-blocking In-Memory TTL Scan Caching: Prevents redundant scans for the
     same host within a configurable TTL window (default 30 mins).
"""

import time
import threading
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional, Tuple


# ── Global High-Reputation Whitelist ──────────────────────────────────────────
# Root domains and service descriptions for verified global infrastructure
SAFE_DOMAINS: Dict[str, str] = {
    # Google / Alphabet / YouTube
    "youtube.com": "YouTube (Google Video Infrastructure)",
    "youtu.be": "YouTube Short Link Service",
    "googlevideo.com": "Google Video CDN",
    "google.com": "Google Search & Core Services",
    "googleapis.com": "Google APIs & Infrastructure",
    "gstatic.com": "Google Static Asset CDN",
    "gmail.com": "Google Workspace / Gmail",
    "googleusercontent.com": "Google User Content CDN",
    
    # Microsoft
    "microsoft.com": "Microsoft Enterprise Infrastructure",
    "azure.com": "Microsoft Azure Cloud Platform",
    "live.com": "Microsoft Live / Outlook",
    "office.com": "Microsoft 365 / Office Cloud",
    "bing.com": "Microsoft Bing Services",
    "windows.com": "Microsoft Windows Update & Services",
    "github.com": "GitHub (Microsoft Developer Platform)",
    "githubusercontent.com": "GitHub User Content CDN",

    # Apple
    "apple.com": "Apple Core Infrastructure",
    "icloud.com": "Apple iCloud Services",
    "cdn-apple.com": "Apple CDN Services",

    # Amazon
    "amazon.com": "Amazon Global Retail & Services",
    "amazonaws.com": "Amazon Web Services (AWS) Infrastructure",
    "cloudfront.net": "Amazon CloudFront Global CDN",

    # Cloudflare & Fastly CDN
    "cloudflare.com": "Cloudflare Global Edge & DDoS Shield",
    "fastly.net": "Fastly Edge Cloud Platform",
    "akamai.com": "Akamai Intelligent Edge Platform",
    "akamaized.net": "Akamai CDN Infrastructure",

    # Social & Media
    "wikipedia.org": "Wikimedia Foundation",
    "wikimedia.org": "Wikimedia Global Media",
    "twitter.com": "X / Twitter Platform",
    "x.com": "X / Twitter Platform",
    "t.co": "X / Twitter Link Service",
    "facebook.com": "Meta / Facebook Platform",
    "fb.com": "Meta / Facebook Services",
    "instagram.com": "Meta / Instagram Platform",
    "linkedin.com": "LinkedIn Enterprise Network",
    "netflix.com": "Netflix Global Streaming CDN",
    "spotify.com": "Spotify Audio Streaming Infrastructure",
    "reddit.com": "Reddit Global Community Platform",
    "yahoo.com": "Yahoo Core Services",

    # Enterprise & Security Vendors
    "zoom.us": "Zoom Video Communications",
    "salesforce.com": "Salesforce Cloud Infrastructure",
    "adobe.com": "Adobe Creative Cloud & Services",
    "oracle.com": "Oracle Cloud Infrastructure",
    "cisco.com": "Cisco Security & Network Infrastructure",
    "ibm.com": "IBM Cloud & Systems",
    "intel.com": "Intel Corporation Infrastructure",
}

# Known Malicious / Blacklisted Domain Patterns
KNOWN_MALICIOUS: Dict[str, str] = {
    "malware-traffic-analysis.net": "Known Malware Analysis & Threat Feed Target",
    "evil-attacker.test": "Simulated Malicious Test Domain",
    "c2-botnet.test": "Simulated C2 Botnet Domain",
    "phishing-sample.test": "Simulated Phishing Domain",
}


class DomainReputationManager:
    """Thread-safe domain reputation evaluator and scan cache manager."""

    def __init__(self, cache_ttl_seconds: int = 1800):
        self.cache_ttl = cache_ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def extract_hostname(target_url: str) -> str:
        """Extract clean lowercase hostname from URL or raw domain string."""
        raw = target_url.strip() if target_url else ""
        if "://" not in raw:
            raw = f"http://{raw}"
        try:
            parsed = urlparse(raw)
            host = (parsed.hostname or target_url).lower().strip()
            # Strip port if present
            if ":" in host:
                host = host.split(":")[0]
            return host
        except Exception:
            return target_url.lower().strip()

    def get_root_domain(self, hostname: str) -> str:
        """Extract root domain (e.g. www.sub.youtube.com -> youtube.com)."""
        parts = hostname.lower().split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname

    def check_reputation(self, target_url: str) -> Dict[str, Any]:
        """Check domain against whitelist and blacklist.
        
        Returns:
            {
                "status": "whitelisted" | "blacklisted" | "unknown",
                "hostname": str,
                "service_name": str,
                "description": str,
                "is_safe": bool
            }
        """
        hostname = self.extract_hostname(target_url)
        root = self.get_root_domain(hostname)

        # Check blacklist first
        for bad_domain, desc in KNOWN_MALICIOUS.items():
            if hostname == bad_domain or hostname.endswith(f".{bad_domain}"):
                return {
                    "status": "blacklisted",
                    "hostname": hostname,
                    "service_name": desc,
                    "description": f"Domain matches known malicious threat intelligence: {bad_domain}",
                    "is_safe": False,
                }

        # Check whitelist (exact or parent domain)
        if hostname in SAFE_DOMAINS:
            service = SAFE_DOMAINS[hostname]
            return {
                "status": "whitelisted",
                "hostname": hostname,
                "service_name": service,
                "description": f"Verified High-Reputation Platform: {service}. Domain has enterprise-grade SSL/TLS and DDoS protection.",
                "is_safe": True,
            }

        if root in SAFE_DOMAINS:
            service = SAFE_DOMAINS[root]
            return {
                "status": "whitelisted",
                "hostname": hostname,
                "service_name": service,
                "description": f"Verified High-Reputation Platform Subdomain: {service}. Domain is protected under verified corporate infrastructure.",
                "is_safe": True,
            }

        # Institutional TLD checks (.gov, .edu, .mil)
        if hostname.endswith(".gov") or hostname.endswith(".gov.eg") or hostname.endswith(".edu") or hostname.endswith(".mil"):
            return {
                "status": "whitelisted",
                "hostname": hostname,
                "service_name": "Government / Educational Institutional Infrastructure",
                "description": "Verified Government/Educational top-level domain with verified governance.",
                "is_safe": True,
            }

        return {
            "status": "unknown",
            "hostname": hostname,
            "service_name": "Standard Internet Target",
            "description": "Standard public or private domain. Proceeding with targeted fast scan.",
            "is_safe": False,
        }

    # ── In-Memory TTL Scan Cache ──────────────────────────────────────────────

    def get_cached_result(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached scan findings if still within TTL."""
        host = self.extract_hostname(target_url)
        with self._lock:
            cached = self._cache.get(host)
            if not cached:
                return None
            elapsed = time.time() - cached.get("timestamp", 0)
            if elapsed > self.cache_ttl:
                del self._cache[host]
                return None
            return cached

    def set_cached_result(self, target_url: str, summary: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        """Store scan findings in cache with current timestamp."""
        host = self.extract_hostname(target_url)
        with self._lock:
            # Simple LRU-like pruning if cache exceeds 500 entries
            if len(self._cache) > 500:
                oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k].get("timestamp", 0))
                del self._cache[oldest_key]

            self._cache[host] = {
                "timestamp": time.time(),
                "summary": summary,
                "findings": findings,
                "host": host,
            }

    def clear_cache(self) -> None:
        """Clear all cached scan entries."""
        with self._lock:
            self._cache.clear()


# Global singleton instance
domain_reputation = DomainReputationManager()
