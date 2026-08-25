"""
HorusShield — SSRF Protection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Single, reusable validator every V-8 Scanner module must call before
accepting or acting on a target. Fixes a confirmed, live-exploited
finding from the Red Team review: `_validate_target_url()` in
routes_vscanner.py checked hostname *format* only, never whether the
target actually resolves somewhere internal — an authenticated user
could point a scan at 127.0.0.1, RFC1918 ranges, or the cloud metadata
endpoint (169.254.169.254) and have it accepted.

WHAT THIS BLOCKS:
- Non-http/https schemes (file://, ftp://, gopher://, dict://, etc.)
- Hostnames that fail to resolve
- Any resolved IP that is private, loopback, link-local, multicast,
  reserved, or unspecified — using Python's own `ipaddress` classification
  (ip.is_private / is_loopback / is_link_local / is_multicast / is_reserved
  / is_unspecified) rather than a hand-maintained CIDR list, so edge cases
  aren't missed the way a manually-copied range list can miss them.
- DNS rebinding at *validation* time: ALL addresses a hostname resolves to
  (IPv4 and IPv6 both) are checked, not just the first one — a hostname
  that resolves to one public and one private IP is rejected.

WHAT THIS DOES NOT FULLY SOLVE (documented honestly, not hidden):
- True DNS-rebinding immunity would require pinning the validated IP and
  connecting directly to it while still sending the original Host header
  — not achievable when the actual requests are made by external
  processes we don't control the socket layer of (Nmap as a subprocess,
  Nikto as a subprocess, ZAP via its own daemon's HTTP client). What this
  module DOES do to narrow that window: the orchestrator re-validates
  immediately before invoking each tool (see vscanner/orchestrator.py),
  not only once at submission time — this closes the gap between "a scan
  was queued" and "a scan actually ran" but cannot close the gap *during*
  ZAP's or Nmap's own multi-request scanning activity once it has started
  making requests to a hostname it already resolved.
- Redirects: enforceable for HTTP requests HorusShield's own code makes
  directly; not enforceable inside Nmap/Nikto/ZAP's own request handling,
  since we don't control their internal HTTP clients.
"""
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = ("http", "https")


class SSRFValidationError(Exception):
    """Raised with a human-readable reason; callers should catch this and
    turn it into a 400 response rather than letting it propagate as a 500."""


def _is_disallowed_ip(ip) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_all_ips(hostname: str) -> list:
    """Resolve a hostname to every IP it points to (IPv4 + IPv6). Raises
    SSRFValidationError if resolution fails outright — an unresolvable
    hostname has no legitimate scan target anyway."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise SSRFValidationError(f"hostname does not resolve: {e}")
    ips = set()
    for info in infos:
        raw_ip = info[4][0]
        try:
            ips.add(ipaddress.ip_address(raw_ip))
        except ValueError:
            continue
    if not ips:
        raise SSRFValidationError("hostname resolved to no usable IP addresses")
    return list(ips)


def validate_target(url: str, allow_private: bool = False) -> dict:
    """Validate a scan target URL end-to-end. Returns
    {"url": normalized_url, "hostname": str, "resolved_ips": [str, ...]}
    on success. Raises SSRFValidationError with a specific reason on
    failure — never silently returns a partially-valid result.

    `allow_private` exists for legitimate internal-network testing (a
    company scanning its own internal app) — it is OFF by default and
    must be explicitly enabled via config (see config.py's
    VSCAN_ALLOW_PRIVATE_TARGETS), never a per-request client-supplied flag,
    so a caller can't just pass allow_private=True to bypass this.
    """
    if not url or not isinstance(url, str):
        raise SSRFValidationError("target URL is required")

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise SSRFValidationError(f"could not parse URL: {e}")

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFValidationError(
            f"scheme '{parsed.scheme}' is not allowed — only {ALLOWED_SCHEMES} are permitted"
        )

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("URL has no hostname")

    # A literal IP in the URL is checked directly; a DNS name is resolved
    # and every resolved address is checked (DNS-rebinding-at-validation-
    # time protection — see module docstring for what this does and does
    # not fully cover).
    try:
        literal_ip = ipaddress.ip_address(hostname.strip("[]"))
        resolved_ips = [literal_ip]
    except ValueError:
        resolved_ips = resolve_all_ips(hostname)

    if not allow_private:
        for ip in resolved_ips:
            if _is_disallowed_ip(ip):
                raise SSRFValidationError(
                    f"target resolves to a disallowed address ({ip}) — "
                    f"private/loopback/link-local/multicast/reserved IPs are blocked. "
                    f"This includes the cloud metadata endpoint 169.254.169.254."
                )

    return {
        "url": url,
        "hostname": hostname,
        "resolved_ips": [str(ip) for ip in resolved_ips],
    }
