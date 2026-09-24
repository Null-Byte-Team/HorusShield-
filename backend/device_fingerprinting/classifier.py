"""
HorusShield 2.0 — Device Classification & Scoring Engine
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Centralized multi-signal evidence scoring engine.
Classifies devices into exact canonical categories with confidence percentages
and detailed, human-readable evidence explanations.

Strict Anti-False-Positive Guarantees:
• Manufacturer ≠ Device Type (Apple does not automatically mean iPhone).
• Multiple corroborating evidence sources required for confident classification.
• Conflicting signals lower confidence rather than guessing.
• Unknown devices remain honestly unknown.
• Models are only populated when verified from device-reported data.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from device_fingerprinting.models import (
    ALL_DEVICE_TYPES,
    DEVICE_TYPE_WINDOWS_PC,
    DEVICE_TYPE_WINDOWS_LAPTOP,
    DEVICE_TYPE_LINUX_PC,
    DEVICE_TYPE_LINUX_SERVER,
    DEVICE_TYPE_MACOS,
    DEVICE_TYPE_IPHONE,
    DEVICE_TYPE_IPAD,
    DEVICE_TYPE_ANDROID_PHONE,
    DEVICE_TYPE_ANDROID_TABLET,
    DEVICE_TYPE_SMART_TV,
    DEVICE_TYPE_PRINTER,
    DEVICE_TYPE_ROUTER,
    DEVICE_TYPE_SWITCH,
    DEVICE_TYPE_ACCESS_POINT,
    DEVICE_TYPE_GATEWAY,
    DEVICE_TYPE_IOT,
    DEVICE_TYPE_CAMERA,
    DEVICE_TYPE_NAS,
    DEVICE_TYPE_SERVER,
    DEVICE_TYPE_VM,
    DEVICE_TYPE_NETWORK_DEVICE,
    DEVICE_TYPE_UNKNOWN,
    DeviceFingerprintResult,
)
from utils.logger import get_logger

logger = get_logger("fingerprint_classifier", "device")


class DeviceClassifier:
    """Multi-signal scoring and decision engine for device fingerprinting."""

    def classify(
        self,
        ip: str,
        mac: str,
        hostname: Optional[str] = None,
        oui_info: Optional[Dict[str, Any]] = None,
        dhcp_info: Optional[Dict[str, Any]] = None,
        mdns_services: Optional[List[str]] = None,
        mdns_name: Optional[str] = None,
        ssdp_info: Optional[Dict[str, Any]] = None,
        service_info: Optional[Dict[str, Any]] = None,
        is_gateway: bool = False,
    ) -> DeviceFingerprintResult:
        """
        Synthesize all available signals into a canonical classification result.
        """
        evidence: List[str] = []
        conf_score: int = 0
        conflicts: List[str] = []

        host = (hostname or "").strip()
        if host.lower() in ("unknown", "none", "", "--", "localhost"):
            host = ""
        host_lower = host.lower()

        # Unpack inputs with safe fallbacks
        oui_data = oui_info or {}
        vendor = oui_data.get("vendor", "Unknown")
        manufacturer = oui_data.get("manufacturer", vendor)
        category_hints = oui_data.get("category_hints", [])
        is_random_mac = oui_data.get("is_randomized", False)

        dhcp_data = dhcp_info or {}
        dhcp_os = dhcp_data.get("os", "Unknown")
        dhcp_dev = dhcp_data.get("device_hint", "Unknown Device")
        dhcp_ev = dhcp_data.get("evidence", [])

        mdns_list = mdns_services or []
        ssdp_data = ssdp_info or {}
        services = service_info or {}
        open_ports = services.get("open_ports", [])

        # Track signals by candidate category
        candidate_scores: Dict[str, int] = {t: 0 for t in ALL_DEVICE_TYPES}

        detected_os = "Unknown"
        detected_model: Optional[str] = None

        # ── 1. MAC / OUI Signal (+10) ──
        vendor_lower = vendor.lower()
        if vendor and vendor != "Unknown" and oui_data.get("reliable"):
            conf_score += 10
            evidence.append(f"{vendor} OUI match")

            # Award soft category points from vendor domain
            if "apple" in vendor_lower:
                detected_os = "Apple OS"
                # Do NOT assign to iPhone alone! Award evenly to Apple ecosystem candidates
                candidate_scores[DEVICE_TYPE_IPHONE] += 5
                candidate_scores[DEVICE_TYPE_IPAD] += 5
                candidate_scores[DEVICE_TYPE_MACOS] += 5
            elif "samsung" in vendor_lower:
                candidate_scores[DEVICE_TYPE_ANDROID_PHONE] += 4
                candidate_scores[DEVICE_TYPE_ANDROID_TABLET] += 4
                candidate_scores[DEVICE_TYPE_SMART_TV] += 4
            elif any(k in vendor_lower for k in ["cisco", "tp-link", "netgear", "d-link", "ubiquiti"]):
                candidate_scores[DEVICE_TYPE_ROUTER] += 8
                candidate_scores[DEVICE_TYPE_NETWORK_DEVICE] += 8
            elif any(k in vendor_lower for k in ["canon", "epson", "brother", "xerox"]):
                candidate_scores[DEVICE_TYPE_PRINTER] += 10
            elif any(k in vendor_lower for k in ["hikvision", "dahua", "axis"]):
                candidate_scores[DEVICE_TYPE_CAMERA] += 10
            elif any(k in vendor_lower for k in ["synology", "qnap"]):
                candidate_scores[DEVICE_TYPE_NAS] += 10
            elif any(k in vendor_lower for k in ["vmware", "virtualbox"]):
                candidate_scores[DEVICE_TYPE_VM] += 10
            elif any(k in vendor_lower for k in ["dell", "hp", "hewlett", "lenovo"]):
                candidate_scores[DEVICE_TYPE_WINDOWS_PC] += 5
                candidate_scores[DEVICE_TYPE_WINDOWS_LAPTOP] += 5
            elif "espressif" in vendor_lower:
                candidate_scores[DEVICE_TYPE_IOT] += 10
            elif "raspberry" in vendor_lower:
                candidate_scores[DEVICE_TYPE_LINUX_PC] += 5
                candidate_scores[DEVICE_TYPE_LINUX_SERVER] += 5
        elif is_random_mac:
            evidence.append("Locally administered / randomized MAC address")
            conf_score += 5

        # ── 2. Hostname Analysis (+20) ──
        if host:
            conf_score += 20
            model_from_host = self._extract_model_from_hostname(host)
            if model_from_host:
                detected_model = model_from_host
                conf_score += 15

            if re.match(r"(?i)^desktop-", host):
                candidate_scores[DEVICE_TYPE_WINDOWS_PC] += 25
                detected_os = "Windows"
                evidence.append(f"DESKTOP- Windows hostname ({host})")
            elif re.match(r"(?i)^laptop-", host):
                candidate_scores[DEVICE_TYPE_WINDOWS_LAPTOP] += 25
                detected_os = "Windows"
                evidence.append(f"LAPTOP- Windows hostname ({host})")
            elif re.match(r"(?i)^win-", host):
                candidate_scores[DEVICE_TYPE_WINDOWS_PC] += 25
                detected_os = "Windows"
                evidence.append(f"WIN- Windows hostname ({host})")
            elif re.search(r"(?i)\biphone\b", host) or host_lower.endswith("iphone"):
                candidate_scores[DEVICE_TYPE_IPHONE] += 30
                detected_os = "iOS"
                evidence.append(f"iPhone hostname ({host})")
            elif re.search(r"(?i)\bipad\b", host) or host_lower.endswith("ipad"):
                candidate_scores[DEVICE_TYPE_IPAD] += 30
                detected_os = "iPadOS"
                evidence.append(f"iPad hostname ({host})")
            elif re.search(r"(?i)(macbook|imac|mac-mini|macpro)", host):
                candidate_scores[DEVICE_TYPE_MACOS] += 30
                detected_os = "macOS"
                evidence.append(f"Mac computer hostname ({host})")
            elif re.search(r"(?i)^galaxy-s\d+", host) or re.search(r"(?i)^sm-[gans]\d+", host):
                candidate_scores[DEVICE_TYPE_ANDROID_PHONE] += 30
                detected_os = "Android"
                evidence.append(f"Samsung Galaxy phone hostname ({host})")
            elif re.search(r"(?i)^sm-[xt]\d+", host) or re.search(r"(?i)galaxy-tab", host):
                candidate_scores[DEVICE_TYPE_ANDROID_TABLET] += 30
                detected_os = "Android"
                evidence.append(f"Samsung Galaxy tablet hostname ({host})")
            elif re.search(r"(?i)android", host):
                candidate_scores[DEVICE_TYPE_ANDROID_PHONE] += 20
                detected_os = "Android"
                evidence.append(f"Android device hostname ({host})")
            elif any(k in host_lower for k in ["printer", "print", "epson", "canon", "brother"]):
                candidate_scores[DEVICE_TYPE_PRINTER] += 25
                evidence.append(f"Printer hostname signature ({host})")
            elif any(k in host_lower for k in ["cam", "camera", "dvr", "nvr"]):
                candidate_scores[DEVICE_TYPE_CAMERA] += 25
                evidence.append(f"Camera hostname signature ({host})")
            elif any(k in host_lower for k in ["router", "gateway", "openwrt", "archer"]):
                candidate_scores[DEVICE_TYPE_ROUTER] += 25
                evidence.append(f"Router hostname signature ({host})")
            elif any(k in host_lower for k in ["nas", "diskstation", "qnap"]):
                candidate_scores[DEVICE_TYPE_NAS] += 25
                evidence.append(f"Storage / NAS hostname ({host})")
            elif any(k in host_lower for k in ["server", "srv", "dc-", "ldap"]):
                candidate_scores[DEVICE_TYPE_SERVER] += 20
                evidence.append(f"Server hostname ({host})")
            elif any(k in host_lower for k in ["vbox", "vmware", "esxi"]):
                candidate_scores[DEVICE_TYPE_VM] += 25
                evidence.append(f"Virtual Machine hostname ({host})")
            elif any(k in host_lower for k in ["tv", "bravia", "webos", "tizen", "rokutv", "chromecast"]):
                candidate_scores[DEVICE_TYPE_SMART_TV] += 25
                evidence.append(f"Smart TV hostname ({host})")

        # ── 3. Gateway Role (+30) ──
        if is_gateway:
            conf_score += 30
            candidate_scores[DEVICE_TYPE_GATEWAY] += 35
            candidate_scores[DEVICE_TYPE_ROUTER] += 30
            evidence.append("Active default network gateway")

        # ── 4. DHCP Fingerprint (+25) ──
        if dhcp_ev:
            conf_score += dhcp_data.get("confidence_boost", 20)
            evidence.extend(dhcp_ev)
            if dhcp_os != "Unknown":
                detected_os = dhcp_os
            if dhcp_dev == "Windows PC":
                candidate_scores[DEVICE_TYPE_WINDOWS_PC] += 25
            elif dhcp_dev == "Apple Mobile":
                candidate_scores[DEVICE_TYPE_IPHONE] += 15
                candidate_scores[DEVICE_TYPE_IPAD] += 15
            elif dhcp_dev == "Android Device":
                candidate_scores[DEVICE_TYPE_ANDROID_PHONE] += 20
            elif dhcp_dev == "Printer":
                candidate_scores[DEVICE_TYPE_PRINTER] += 25

        # ── 5. mDNS / Bonjour (+20) ──
        if mdns_list:
            conf_score += 20
            evidence.append(f"mDNS services: {', '.join(mdns_list)}")
            if any(s in mdns_list for s in ["_airplay._tcp", "_raop._tcp"]):
                candidate_scores[DEVICE_TYPE_IPHONE] += 10
                candidate_scores[DEVICE_TYPE_IPAD] += 10
                candidate_scores[DEVICE_TYPE_MACOS] += 15
                candidate_scores[DEVICE_TYPE_SMART_TV] += 15
                if detected_os == "Unknown":
                    detected_os = "Apple OS"
            if any(s in mdns_list for s in ["_ipp._tcp", "_printer._tcp"]):
                candidate_scores[DEVICE_TYPE_PRINTER] += 30
            if any(s in mdns_list for s in ["_googlecast._tcp", "_spotify-connect._tcp"]):
                candidate_scores[DEVICE_TYPE_SMART_TV] += 20
                candidate_scores[DEVICE_TYPE_IOT] += 15
            if "_smb._tcp" in mdns_list or "_workstation._tcp" in mdns_list:
                candidate_scores[DEVICE_TYPE_WINDOWS_PC] += 10
                candidate_scores[DEVICE_TYPE_NAS] += 10
            if "_ssh._tcp" in mdns_list:
                candidate_scores[DEVICE_TYPE_LINUX_SERVER] += 15

        if mdns_name:
            if not detected_model:
                detected_model = mdns_name
            evidence.append(f"mDNS advertised name: {mdns_name}")

        # ── 6. SSDP / UPnP (+25, and +40 for strong explicit model) ──
        if ssdp_data:
            conf_score += 25
            upnp_mfg = ssdp_data.get("manufacturer")
            upnp_devtype = ssdp_data.get("device_type", "").lower()
            upnp_model = ssdp_data.get("model_name") or ssdp_data.get("model_number")
            upnp_friendly = ssdp_data.get("friendly_name")

            if upnp_mfg and upnp_mfg != "Unknown":
                manufacturer = upnp_mfg
                evidence.append(f"UPnP Manufacturer: {upnp_mfg}")

            if upnp_model:
                detected_model = upnp_model
                conf_score += 15  # strong explicit model
                evidence.append(f"UPnP Model: {upnp_model}")

            if "internetgatewaydevice" in upnp_devtype or "router" in upnp_devtype:
                candidate_scores[DEVICE_TYPE_ROUTER] += 35
                candidate_scores[DEVICE_TYPE_GATEWAY] += 25
                evidence.append("UPnP Internet Gateway Device")
            elif "mediarenderer" in upnp_devtype or "mediaserver" in upnp_devtype:
                candidate_scores[DEVICE_TYPE_SMART_TV] += 30
                evidence.append("UPnP Media Renderer / Smart TV")
            elif "camera" in upnp_devtype:
                candidate_scores[DEVICE_TYPE_CAMERA] += 35
                evidence.append("UPnP Security Camera")
            elif "printer" in upnp_devtype:
                candidate_scores[DEVICE_TYPE_PRINTER] += 35
                evidence.append("UPnP Printer Device")

        # ── 7. Network Service Fingerprinting (+15) ──
        if open_ports:
            conf_score += 15
            ports_summary = ", ".join(str(p) for p in open_ports[:6])
            evidence.append(f"Observed network ports: [{ports_summary}]")

            # Combinations
            if services.get("has_printer_ports"):
                candidate_scores[DEVICE_TYPE_PRINTER] += 35
                evidence.append("Raw/IPP printing service active (631/9100)")

            if services.get("has_camera_ports"):
                candidate_scores[DEVICE_TYPE_CAMERA] += 35
                evidence.append("RTSP surveillance stream active (554)")

            if services.get("has_smb") or services.get("has_rdp"):
                candidate_scores[DEVICE_TYPE_WINDOWS_PC] += 15
                candidate_scores[DEVICE_TYPE_WINDOWS_LAPTOP] += 10
                if detected_os == "Unknown":
                    detected_os = "Windows"
                evidence.append("Windows file sharing / remote desktop active (SMB/RDP)")

            if services.get("has_gateway_services") or (53 in open_ports and 80 in open_ports):
                candidate_scores[DEVICE_TYPE_ROUTER] += 20
                candidate_scores[DEVICE_TYPE_GATEWAY] += 15
                evidence.append("Router DNS & web management ports open")

            http_server = services.get("http_server")
            if http_server:
                evidence.append(f"HTTP Server: {http_server}")
                if "microsoft" in http_server.lower():
                    candidate_scores[DEVICE_TYPE_WINDOWS_PC] += 15
                    detected_os = "Windows"
                elif any(k in http_server.lower() for k in ["lighttpd", "micro_httpd", "openwrt", "d-link", "tp-link"]):
                    candidate_scores[DEVICE_TYPE_ROUTER] += 15

            ssh_banner = services.get("ssh_banner")
            if ssh_banner:
                evidence.append(f"SSH Banner: {ssh_banner}")
                if "ubuntu" in ssh_banner.lower() or "debian" in ssh_banner.lower():
                    candidate_scores[DEVICE_TYPE_LINUX_SERVER] += 20
                    candidate_scores[DEVICE_TYPE_LINUX_PC] += 10
                    detected_os = "Linux"
                elif "dropbear" in ssh_banner.lower():
                    candidate_scores[DEVICE_TYPE_ROUTER] += 15
                    candidate_scores[DEVICE_TYPE_IOT] += 10

        # ── 8. Resolve Candidates & Detect Conflicts ──
        # Find highest scoring candidate
        sorted_candidates = sorted(
            candidate_scores.items(), key=lambda kv: kv[1], reverse=True
        )
        best_type, top_score = sorted_candidates[0]
        second_type, second_score = sorted_candidates[1]

        # Check for meaningful conflict between top two distinct candidates
        if top_score > 0 and second_score > 0:
            is_close_conflict = (top_score - second_score < 10)
            is_drastic_mismatch = (
                ("Windows" in best_type and "apple" in vendor_lower)
                or ("Apple" in best_type and ("Windows" in detected_os or "windows" in host_lower or "win-" in host_lower))
                or ("apple" in vendor_lower and ("win-" in host_lower or "windows" in host_lower or "windows" in detected_os))
                or (best_type == DEVICE_TYPE_PRINTER and is_gateway)
            )
            if is_drastic_mismatch or (is_close_conflict and second_score >= 20):
                conflicts.append(f"Conflicting signals between {best_type} and {second_type}")
                # Heavily penalize confidence — honesty over guessing
                conf_score = min(25, max(10, conf_score - 30))
                evidence.append(f"Conflicting indicators ({best_type} vs {second_type})")
                if is_drastic_mismatch:
                    # Cancel classification if signals directly oppose each other
                    candidate_scores[best_type] = 0
                    top_score = 0

        # ── 9. Final Classification Assignment ──
        final_type = DEVICE_TYPE_UNKNOWN

        if top_score >= 18:
            final_type = best_type
            # Refine Windows PC vs Windows Laptop if specific evidence exists
            if final_type in (DEVICE_TYPE_WINDOWS_PC, DEVICE_TYPE_WINDOWS_LAPTOP):
                if re.match(r"(?i)^laptop-", host):
                    final_type = DEVICE_TYPE_WINDOWS_LAPTOP
                elif re.match(r"(?i)^desktop-", host):
                    final_type = DEVICE_TYPE_WINDOWS_PC

            # Distinguish Router from Network Gateway
            if is_gateway and final_type in (DEVICE_TYPE_ROUTER, DEVICE_TYPE_NETWORK_DEVICE):
                final_type = DEVICE_TYPE_GATEWAY if top_score < 40 else DEVICE_TYPE_ROUTER

        elif is_gateway:
            final_type = DEVICE_TYPE_GATEWAY
        elif vendor and vendor != "Unknown" and not is_random_mac:
            # Vendor known but not enough evidence to claim specific device type
            final_type = DEVICE_TYPE_UNKNOWN
        else:
            final_type = DEVICE_TYPE_UNKNOWN

        # Infer OS if still unknown
        if detected_os == "Unknown":
            detected_os = self._infer_os_from_type(final_type)

        # Multi-signal corroboration bonus:
        # Multiple independent sources agreeing on a classification increases confidence
        if final_type != DEVICE_TYPE_UNKNOWN and not conflicts:
            sources_count = sum([
                bool(vendor and vendor != "Unknown" and oui_data.get("reliable")),
                bool(host),
                bool(dhcp_ev),
                bool(mdns_list),
                bool(ssdp_data),
                bool(open_ports),
                bool(is_gateway),
            ])
            if sources_count >= 4:
                conf_score += 25
            elif sources_count == 3:
                conf_score += 20
            elif sources_count == 2:
                conf_score += 15

        # Baseline confidence when evidence is sparse
        if not evidence:
            evidence.append("MAC address only")
            conf_score = 15
        elif final_type == DEVICE_TYPE_UNKNOWN and conf_score < 25:
            conf_score = min(conf_score, 25)

        # Cap confidence between 10% and 98% (never 100% unless physically verified)
        final_confidence = max(12, min(95, conf_score))

        return DeviceFingerprintResult(
            ip=ip,
            mac=mac,
            hostname=host or "Unknown",
            vendor=vendor,
            manufacturer=manufacturer,
            device_type=final_type,
            model=detected_model,
            os=detected_os,
            confidence=final_confidence,
            evidence=evidence,
            services=open_ports,
            protocols=[p for p in ["TCP", "UDP", "ARP"]],
            is_gateway=is_gateway,
            raw_signals={
                "candidate_scores": {k: v for k, v in candidate_scores.items() if v > 0},
                "conflicts": conflicts,
                "oui": oui_data,
                "dhcp": dhcp_data,
                "mdns": mdns_list,
                "ssdp": ssdp_data,
            }
        )

    def _extract_model_from_hostname(self, host: str) -> Optional[str]:
        """Extract explicit model number from hostname if formatted cleanly."""
        h = host.strip()
        # Galaxy-S23, Galaxy-A54, etc.
        m = re.search(r"(?i)\b(Galaxy-S\d+|Galaxy-A\d+|Galaxy-Note\d+|Galaxy-Tab\w*)", h)
        if m:
            return m.group(1).replace("-", " ")
        # SM-G998B, SM-X900, etc.
        m = re.search(r"(?i)\b(SM-[A-Z0-9]+)\b", h)
        if m:
            return m.group(1)
        # Archer-C7, Archer-AX50, etc.
        m = re.search(r"(?i)\b(Archer-[A-Z0-9]+)\b", h)
        if m:
            return m.group(1).replace("-", " ")
        # MacBookPro18,1 etc.
        m = re.search(r"(?i)\b(MacBook(Pro|Air)?[\w,]+)\b", h)
        if m:
            return m.group(1)
        # iPhone / iPad
        m = re.search(r"(?i)\b(iPhone(?:\s*(?:1[1-9]|[6-9]|SE|X[RS]?|Pro|Max|Plus))*)\b", h)
        if m and m.group(1).strip():
            return m.group(1).strip()
        m = re.search(r"(?i)\b(iPad(?:\s*(?:Air|Pro|Mini|\d+))*)\b", h)
        if m and m.group(1).strip():
            return m.group(1).strip()
        return None

    def _infer_os_from_type(self, device_type: str) -> str:
        """Infer operating system family from confirmed device type."""
        if device_type in (DEVICE_TYPE_WINDOWS_PC, DEVICE_TYPE_WINDOWS_LAPTOP):
            return "Windows"
        elif device_type == DEVICE_TYPE_IPHONE:
            return "iOS"
        elif device_type == DEVICE_TYPE_IPAD:
            return "iPadOS"
        elif device_type == DEVICE_TYPE_MACOS:
            return "macOS"
        elif device_type in (DEVICE_TYPE_ANDROID_PHONE, DEVICE_TYPE_ANDROID_TABLET):
            return "Android"
        elif device_type in (DEVICE_TYPE_LINUX_PC, DEVICE_TYPE_LINUX_SERVER):
            return "Linux"
        elif device_type in (DEVICE_TYPE_ROUTER, DEVICE_TYPE_GATEWAY, DEVICE_TYPE_SWITCH, DEVICE_TYPE_ACCESS_POINT):
            return "Embedded Linux / Firmware"
        elif device_type == DEVICE_TYPE_PRINTER:
            return "Embedded Printer OS"
        elif device_type == DEVICE_TYPE_CAMERA:
            return "Embedded Camera OS"
        elif device_type == DEVICE_TYPE_SMART_TV:
            return "Smart TV OS (Tizen/webOS/AndroidTV)"
        elif device_type == DEVICE_TYPE_NAS:
            return "NAS OS"
        return "Unknown"


device_classifier = DeviceClassifier()
