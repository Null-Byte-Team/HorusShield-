"""
HorusShield — Centralized Client-IP Resolution
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Fixes a confirmed finding from the Red Team review: every audit-log write
site trusted the `X-Forwarded-For` request header unconditionally, with
no check that the request actually came through a real reverse proxy.
Sending `X-Forwarded-For: <anything>` caused that value to be written
verbatim into the audit trail — a request from one real IP could plant
an entirely different, attacker-chosen IP in HorusShield's own forensic
record.

Every route that needs the client IP for logging must call
`get_client_ip()` from this module — there is intentionally only one
implementation, not one per blueprint, so behavior can't drift.

Behavior:
- `config.TRUST_PROXY = False` (the default): X-Forwarded-For is IGNORED
  entirely, regardless of what it contains. `request.remote_addr` — the
  actual TCP peer address Flask/Werkzeug saw — is used. This cannot be
  spoofed by a request header.
- `config.TRUST_PROXY = True`: only set this when HorusShield is actually
  deployed behind a real reverse proxy that sets X-Forwarded-For itself
  (nginx, a cloud load balancer, etc.). The chain is parsed safely: with
  `TRUST_PROXY_HOPS = N` (default 1), the Nth-from-the-right entry in the
  X-Forwarded-For chain is used — everything to the right of that is
  trusted proxy hops that get skipped, and the value used is still
  validated as a syntactically real IP address before being trusted.
  Malformed entries fail closed to `request.remote_addr`, not silently
  accepted as-is.
"""
import ipaddress

from flask import request

from config import active_config as config


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def get_client_ip() -> str:
    """The one function every route should call to log a client's IP.
    Never raises — worst case returns an empty string.
    """
    remote_addr = request.remote_addr or ""

    if not config.TRUST_PROXY:
        return remote_addr

    xff = request.headers.get("X-Forwarded-For", "")
    if not xff:
        return remote_addr

    # X-Forwarded-For is a comma-separated chain, left = original client,
    # right = each proxy hop closer to us. With TRUST_PROXY_HOPS proxies
    # actually in front of us, the real client is TRUST_PROXY_HOPS entries
    # from the right.
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    if not hops:
        return remote_addr

    hop_count = max(1, config.TRUST_PROXY_HOPS)
    if len(hops) < hop_count:
        # Chain is shorter than the configured trusted-proxy count —
        # malformed/unexpected, fail closed rather than guess.
        return remote_addr

    candidate = hops[-hop_count]
    if not _is_valid_ip(candidate):
        # Reject malformed values outright rather than trusting them —
        # this is exactly the gap that made spoofing possible before.
        return remote_addr

    return candidate
