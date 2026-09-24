"""
HorusShield 2.0 — DHCP Fingerprinting Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Passive DHCP packet analysis for OS and client device fingerprinting.
Parses Option 55 (Parameter Request List), Option 60 (Vendor Class Identifier),
and Option 12 (Host Name). Gracefully skips when DHCP data is absent.
"""

import threading
from typing import Any, Dict, List, Optional, Tuple


from utils.logger import get_logger

logger = get_logger("fingerprint_dhcp", "device")

# Standard Option 55 Parameter Request Lists (comma-separated option numbers)
_KNOWN_OPTION55_MAP: Dict[str, Tuple[str, str, int]] = {
    # Option 55 sequence -> (OS Family, Device Category, Confidence Weight)
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252": ("Windows", "Windows PC", 25),
    "1,15,3,6,44,46,47,31,33,121,249,252,43": ("Windows", "Windows PC", 25),
    "1,3,6,15,31,33,43,44,46,47,121,249,252": ("Windows", "Windows PC", 25),
    "1,121,3,6,15,114,119,252": ("iOS", "Apple Mobile", 25),
    "1,3,6,15,119,252": ("iOS", "Apple Mobile", 20),
    "1,121,3,6,15,119,252,95,44,46": ("macOS", "macOS Computer", 25),
    "1,3,6,15,26,28,51,58,59,43": ("Android", "Android Device", 25),
    "1,3,6,15,26,28,51,58,59,43,114,108": ("Android", "Android Device", 25),
    "1,3,6,12,15,26,28,33,42": ("Linux", "Linux Device", 20),
    "1,28,2,3,15,6,119,12,44,47,26,121,42": ("Linux", "Linux Device", 20),
}


class DHCPFingerprinter:
    """Thread-safe store and analyzer for observed DHCP fingerprints."""

    _instance: Optional["DHCPFingerprinter"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "DHCPFingerprinter":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._cache: Dict[str, Dict[str, Any]] = {}
                    cls._instance._cache_lock = threading.Lock()
        return cls._instance

    def record_dhcp_signal(
        self,
        mac: str,
        option55: Optional[str] = None,
        vendor_class: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> None:
        """Store observed DHCP options for a MAC address."""
        if not mac:
            return
        mac_key = mac.upper()
        with self._cache_lock:
            entry = self._cache.setdefault(mac_key, {})
            if option55:
                entry["option55"] = option55
            if vendor_class:
                entry["vendor_class"] = vendor_class
            if hostname:
                entry["hostname"] = hostname

    def get_fingerprint(self, mac: str) -> Optional[Dict[str, Any]]:
        """Retrieve and analyze recorded DHCP fingerprint for a MAC."""
        if not mac:
            return None
        mac_key = mac.upper()
        with self._cache_lock:
            data = self._cache.get(mac_key)
        if not data:
            return None

        return self.analyze_options(
            option55=data.get("option55"),
            vendor_class=data.get("vendor_class"),
            hostname=data.get("hostname"),
        )

    def analyze_options(
        self,
        option55: Optional[str] = None,
        vendor_class: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyze DHCP options and return OS/device category hints with confidence.
        """
        evidence: List[str] = []
        os_hint = "Unknown"
        device_hint = "Unknown Device"
        confidence_boost = 0

        # Analyze Option 60 (Vendor Class Identifier)
        if vendor_class:
            vc_lower = vendor_class.lower()
            evidence.append(f"DHCP Vendor Class: {vendor_class}")
            if "msft 5.0" in vc_lower or "microsoft" in vc_lower:
                os_hint = "Windows"
                device_hint = "Windows PC"
                confidence_boost = max(confidence_boost, 25)
            elif "android-dhcp-" in vc_lower:
                os_hint = "Android"
                device_hint = "Android Device"
                confidence_boost = max(confidence_boost, 25)
            elif any(k in vc_lower for k in ["apple", "darwin"]):
                os_hint = "iOS/macOS"
                device_hint = "Apple Device"
                confidence_boost = max(confidence_boost, 20)
            elif "dhcpcd" in vc_lower or "isc-dhcp" in vc_lower or "ubuntu" in vc_lower:
                os_hint = "Linux"
                device_hint = "Linux Device"
                confidence_boost = max(confidence_boost, 20)
            elif "jetdirect" in vc_lower or "printer" in vc_lower:
                os_hint = "Embedded"
                device_hint = "Printer"
                confidence_boost = max(confidence_boost, 25)

        # Analyze Option 55 (Parameter Request List)
        if option55:
            opt_str = str(option55).strip()
            if opt_str in _KNOWN_OPTION55_MAP:
                detected_os, detected_dev, score = _KNOWN_OPTION55_MAP[opt_str]
                os_hint = detected_os
                device_hint = detected_dev
                confidence_boost = max(confidence_boost, score)
                evidence.append(f"DHCP Option 55 signature: {detected_os}")
            else:
                evidence.append(f"DHCP Option 55 captured ({opt_str[:20]}...)")

        return {
            "os": os_hint,
            "device_hint": device_hint,
            "confidence_boost": confidence_boost,
            "evidence": evidence,
            "option55": option55,
            "vendor_class": vendor_class,
        }


dhcp_fingerprinter = DHCPFingerprinter()
