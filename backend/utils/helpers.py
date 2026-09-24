"""
HorusShield Helper Utilities
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Common utility functions used across modules.
"""

import socket
import json
import hashlib
import random
import time
import platform
import ipaddress
from datetime import datetime


def get_local_ip():
    """Get the local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_network_range(ip=None):
    """Get the network range (CIDR) for scanning."""
    details = get_primary_ipv4_details(ip)
    try:
        if details["ip"] and details["netmask"]:
            return str(ipaddress.ip_network(f"{details['ip']}/{details['netmask']}", strict=False))
    except Exception:
        pass

    if ip is None:
        ip = get_local_ip()
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def get_primary_ipv4_details(ip=None):
    """Return the primary IPv4 address and netmask for the current host."""
    target_ip = ip or get_local_ip()
    try:
        import psutil

        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if getattr(addr, "family", None) != socket.AF_INET:
                    continue
                if not addr.address or addr.address.startswith("127."):
                    continue
                if target_ip and addr.address != target_ip:
                    continue
                return {
                    "ip": addr.address,
                    "netmask": addr.netmask or "255.255.255.0",
                }
    except Exception:
        pass

    return {
        "ip": target_ip,
        "netmask": "255.255.255.0",
    }


def get_local_ipv4_addresses():
    """Return all non-loopback IPv4 addresses assigned to this host."""
    addresses = set()
    try:
        import psutil

        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if getattr(addr, "family", None) == socket.AF_INET and addr.address and not addr.address.startswith("127."):
                    addresses.add(addr.address)
    except Exception:
        pass

    if not addresses:
        addresses.add(get_local_ip())
    return addresses


def synthetic_mac_from_ip(ip):
    """Build a deterministic locally-administered MAC for hosts without a real MAC."""
    try:
        octets = [int(part) & 0xFF for part in str(ip).split(".")]
        if len(octets) == 4:
            return f"02:00:{octets[0]:02X}:{octets[1]:02X}:{octets[2]:02X}:{octets[3]:02X}"
    except Exception:
        pass

    # usedforsecurity=False: this MD5 use is a fast, deterministic hash for
    # generating a display-only synthetic MAC identifier from an IP —
    # never used for anything security-sensitive (auth tokens use
    # secrets.token_urlsafe(), not this). Flagged by bandit (B324); marking
    # explicitly rather than suppressing, since the flag is correct that
    # MD5 is weak — it's just not being relied on for security here.
    digest = hashlib.md5(str(ip).encode(), usedforsecurity=False).digest()[:4]
    return "02:00:" + ":".join(f"{byte:02X}" for byte in digest)


def get_gateway_ip():
    """Get the default gateway IP."""
    try:
        if platform.system() == "Windows":
            import subprocess
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split("\n"):
                if "Default Gateway" in line or "البوابة الافتراضية" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        gw = parts[1].strip()
                        if gw:
                            return gw
        else:
            import subprocess
            result = subprocess.run(
                ["ip", "route", "show", "default"], capture_output=True, text=True, timeout=10
            )
            parts = result.stdout.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None


def get_hostname(ip):
    """Resolve hostname from IP."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return "Unknown"


def mac_to_vendor(mac_address):
    """Get vendor from MAC address OUI."""
    try:
        from mac_vendor_lookup import MacLookup
        lookup = MacLookup()
        return lookup.lookup(mac_address)
    except Exception:
        # Fallback common vendors
        oui = mac_address.upper().replace(":", "").replace("-", "")[:6]
        COMMON_VENDORS = {
            "001A2B": "Ayecom Technology",
            "00505E": "Accton Technology",
            "3C5AB4": "Google",
            "F8FF0A": "Broadcom",
            "AABBCC": "Apple",
            "D8BB2C": "Apple",
            "3CE072": "Apple",
            "B0BE76": "Samsung",
            "AC36D3": "Samsung",
            "001E65": "Intel",
            "54271E": "Intel",
            "F81654": "Intel",
            "00E04C": "Realtek",
            "00D861": "Micro-Star",
            "B42E99": "Glenyre",
        }
        return COMMON_VENDORS.get(oui, "Unknown Vendor")


def classify_device_type(hostname, vendor, open_ports=None):
    """Classify device type using the centralized Device Fingerprinting Engine."""
    try:
        from device_fingerprinting.classifier import device_classifier
        from device_fingerprinting.oui import lookup_oui

        oui_info = {"vendor": vendor or "Unknown", "reliable": bool(vendor and vendor != "Unknown")}
        service_info = {"open_ports": open_ports or []}
        result = device_classifier.classify(
            ip="",
            mac="",
            hostname=hostname,
            oui_info=oui_info,
            service_info=service_info,
        )
        return result.device_type
    except Exception:
        # Graceful fallback if module isn't loaded
        return "Unknown Device"



def severity_to_number(severity):
    """Convert severity string to numeric value."""
    mapping = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1,
    }
    return mapping.get(severity.lower(), 1)


def number_to_severity(number):
    """Convert numeric value to severity string."""
    mapping = {5: 'critical', 4: 'high', 3: 'medium', 2: 'low', 1: 'info'}
    return mapping.get(number, 'info')


def generate_session_id():
    """Generate a unique ID for scans/honeypot sessions — NOT an
    authentication credential (real auth tokens use
    auth_manager.py's secrets.token_urlsafe(48), a cryptographically
    secure generator). usedforsecurity=False marks this MD5 use
    explicitly as non-cryptographic (id formatting only) — bandit (B324)
    correctly flags MD5 as weak in general; this confirms it's not being
    relied on for security here.
    """
    return hashlib.md5(
        f"{time.time()}-{random.randint(0, 999999)}".encode(), usedforsecurity=False
    ).hexdigest()[:16]


def format_bytes(bytes_count):
    """Format bytes into human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024
    return f"{bytes_count:.1f} PB"


def format_packets(count):
    """Format packet count."""
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    if count >= 1_000:
        return f"{count / 1_000:.1f}K"
    return str(count)


def time_ago(timestamp_str):
    """Convert timestamp to 'time ago' string."""
    try:
        if isinstance(timestamp_str, str):
            ts = datetime.fromisoformat(timestamp_str)
        else:
            ts = timestamp_str
        diff = datetime.utcnow() - ts
        seconds = diff.total_seconds()

        if seconds < 60:
            return "just now"
        if seconds < 3600:
            return f"{int(seconds / 60)}m ago"
        if seconds < 86400:
            return f"{int(seconds / 3600)}h ago"
        return f"{int(seconds / 86400)}d ago"
    except Exception:
        return "unknown"


def is_private_ip(ip):
    """Check if an IP is in a private range."""
    try:
        parts = [int(p) for p in ip.split(".")]
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        return False
    except Exception:
        return False


def entropy(data):
    """Calculate Shannon entropy of a byte string."""
    if not data:
        return 0.0
    import math
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def random_mac():
    """Generate a random MAC address."""
    return ":".join(f"{random.randint(0x00, 0xff):02x}" for _ in range(6))


def random_ip(subnet="192.168.1"):
    """Generate a random IP in a subnet."""
    return f"{subnet}.{random.randint(2, 254)}"


def pdf_safe_text(text) -> str:
    """Make arbitrary text safe to pass into fpdf2's core (Latin-1-only)
    fonts. Report data can come from third-party tools scanning attacker-
    controlled targets (page titles, headers, Nikto/ZAP findings) — any
    single unsupported character (smart quotes, em-dashes, emoji, non-Latin
    scripts) would otherwise raise FPDFUnicodeEncodingException and abort
    the whole report. This first swaps common punctuation for ASCII
    equivalents, then replaces anything still outside Latin-1 with '?'
    instead of crashing.
    """
    if text is None:
        return ""
    text = str(text)
    replacements = {
        "\u2014": "-", "\u2013": "-",       # em dash, en dash
        "\u2018": "'", "\u2019": "'",       # smart single quotes
        "\u201c": '"', "\u201d": '"',       # smart double quotes
        "\u2026": "...",                     # ellipsis
        "\u2022": "-",                       # bullet
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def safe_json_loads(data, default=None):
    """Safely load JSON data."""
    try:
        return json.loads(data) if data else (default or {})
    except (json.JSONDecodeError, TypeError):
        return default or {}
