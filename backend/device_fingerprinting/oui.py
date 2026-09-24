"""
HorusShield 2.0 — MAC / OUI Identification Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Accurate manufacturer identification using 24-bit OUI prefixes.
Maintains a rich local OUI database and normalizes manufacturer names.

IMPORTANT:
Manufacturer ≠ Device Type.
Apple could be iPhone, iPad, Mac, Apple TV, or Apple Watch.
OUI is strictly treated as one evidence signal among many.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import get_logger

logger = get_logger("fingerprint_oui", "device")

# ── Extensive Maintained Local OUI Database ──
# Maps 6-character hex OUI prefixes to (Manufacturer Name, Category Hints)
_KNOWN_OUIS: Dict[str, Tuple[str, List[str]]] = {
    # Apple
    "000393": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "000502": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "000A27": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "000A95": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "001124": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "001451": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "0016CB": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "0017F2": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "0019E3": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "001B63": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "001C42": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "001D4F": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "001E52": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "001F5B": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "0021E9": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "002241": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "002312": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "002332": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "00236C": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "002436": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "002500": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "00254B": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "002608": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "00264A": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "0026B0": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "0026BB": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "28CFE9": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "3C0754": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "3CE072": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "AABBCC": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "D8BB2C": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "BC9FEF": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "F01898": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "ACDE48": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "F4F15A": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),
    "FC253F": ("Apple, Inc.", ["computer", "phone", "tablet", "media"]),

    # Samsung
    "0000F0": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "000278": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "0007AB": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "000D4B": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "0012FB": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "001377": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "001599": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "00166C": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "0018AF": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "0021D1": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "002637": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "B0BE76": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "AC36D3": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "508569": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "E47CF9": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "946372": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "C81479": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),
    "60A10A": ("Samsung Electronics", ["phone", "tablet", "tv", "iot"]),

    # Huawei
    "001E10": ("HUAWEI TECHNOLOGIES CO., LTD", ["phone", "network", "router", "laptop"]),
    "00259E": ("HUAWEI TECHNOLOGIES CO., LTD", ["phone", "network", "router", "laptop"]),
    "2469A5": ("HUAWEI TECHNOLOGIES CO., LTD", ["phone", "network", "router", "laptop"]),
    "4846FB": ("HUAWEI TECHNOLOGIES CO., LTD", ["phone", "network", "router", "laptop"]),
    "70723C": ("HUAWEI TECHNOLOGIES CO., LTD", ["phone", "network", "router", "laptop"]),
    "AC853D": ("HUAWEI TECHNOLOGIES CO., LTD", ["phone", "network", "router", "laptop"]),
    "C8D15E": ("HUAWEI TECHNOLOGIES CO., LTD", ["phone", "network", "router", "laptop"]),
    "DC094C": ("HUAWEI TECHNOLOGIES CO., LTD", ["phone", "network", "router", "laptop"]),

    # Xiaomi
    "640980": ("Xiaomi Communications Co Ltd", ["phone", "tablet", "tv", "iot"]),
    "286C07": ("Xiaomi Communications Co Ltd", ["phone", "tablet", "tv", "iot"]),
    "7C1DFA": ("Xiaomi Communications Co Ltd", ["phone", "tablet", "tv", "iot"]),
    "ACF1DF": ("Xiaomi Communications Co Ltd", ["phone", "tablet", "tv", "iot"]),
    "508F4C": ("Xiaomi Communications Co Ltd", ["phone", "tablet", "tv", "iot"]),
    "7811DC": ("Xiaomi Communications Co Ltd", ["phone", "tablet", "tv", "iot"]),

    # Hewlett Packard / HP
    "0001E6": ("Hewlett Packard", ["computer", "laptop", "printer", "server"]),
    "000802": ("Hewlett Packard", ["computer", "laptop", "printer", "server"]),
    "000E7F": ("Hewlett Packard", ["computer", "laptop", "printer", "server"]),
    "001E0B": ("Hewlett Packard", ["computer", "laptop", "printer", "server"]),
    "0025B3": ("Hewlett Packard", ["computer", "laptop", "printer", "server"]),
    "6C3BE5": ("Hewlett Packard", ["computer", "laptop", "printer", "server"]),
    "A45D36": ("Hewlett Packard", ["computer", "laptop", "printer", "server"]),
    "3C5282": ("Hewlett Packard", ["computer", "laptop", "printer", "server"]),
    "D89D67": ("Hewlett Packard", ["computer", "laptop", "printer", "server"]),
    "FC3FDB": ("Hewlett Packard", ["computer", "laptop", "printer", "server"]),

    # Dell
    "00065B": ("Dell Inc.", ["computer", "laptop", "server"]),
    "001422": ("Dell Inc.", ["computer", "laptop", "server"]),
    "00188B": ("Dell Inc.", ["computer", "laptop", "server"]),
    "0026B9": ("Dell Inc.", ["computer", "laptop", "server"]),
    "5CF9DD": ("Dell Inc.", ["computer", "laptop", "server"]),
    "1866DA": ("Dell Inc.", ["computer", "laptop", "server"]),
    "B82A72": ("Dell Inc.", ["computer", "laptop", "server"]),
    "F8BC12": ("Dell Inc.", ["computer", "laptop", "server"]),

    # Lenovo
    "0012FE": ("Lenovo", ["computer", "laptop", "tablet"]),
    "005907": ("Lenovo", ["computer", "laptop", "tablet"]),
    "482C6A": ("Lenovo", ["computer", "laptop", "tablet"]),
    "6C5940": ("Lenovo", ["computer", "laptop", "tablet"]),
    "8CE748": ("Lenovo", ["computer", "laptop", "tablet"]),
    "E02BE9": ("Lenovo", ["computer", "laptop", "tablet"]),

    # Intel
    "0002B3": ("Intel Corporate", ["computer", "laptop", "server", "network"]),
    "000347": ("Intel Corporate", ["computer", "laptop", "server", "network"]),
    "000E0C": ("Intel Corporate", ["computer", "laptop", "server", "network"]),
    "001302": ("Intel Corporate", ["computer", "laptop", "server", "network"]),
    "001E65": ("Intel Corporate", ["computer", "laptop", "server", "network"]),
    "54271E": ("Intel Corporate", ["computer", "laptop", "server", "network"]),
    "F81654": ("Intel Corporate", ["computer", "laptop", "server", "network"]),
    "8086F2": ("Intel Corporate", ["computer", "laptop", "server", "network"]),
    "A0AFBD": ("Intel Corporate", ["computer", "laptop", "server", "network"]),

    # Cisco
    "00000C": ("Cisco Systems, Inc", ["network", "router", "switch", "ap"]),
    "000142": ("Cisco Systems, Inc", ["network", "router", "switch", "ap"]),
    "000143": ("Cisco Systems, Inc", ["network", "router", "switch", "ap"]),
    "000196": ("Cisco Systems, Inc", ["network", "router", "switch", "ap"]),
    "0001C7": ("Cisco Systems, Inc", ["network", "router", "switch", "ap"]),
    "000BD5": ("Cisco Systems, Inc", ["network", "router", "switch", "ap"]),
    "001E13": ("Cisco Systems, Inc", ["network", "router", "switch", "ap"]),
    "503DE5": ("Cisco Systems, Inc", ["network", "router", "switch", "ap"]),

    # TP-Link
    "001478": ("TP-Link Technologies Co., Ltd.", ["network", "router", "switch", "ap", "iot"]),
    "0019E0": ("TP-Link Technologies Co., Ltd.", ["network", "router", "switch", "ap", "iot"]),
    "002127": ("TP-Link Technologies Co., Ltd.", ["network", "router", "switch", "ap", "iot"]),
    "0023CD": ("TP-Link Technologies Co., Ltd.", ["network", "router", "switch", "ap", "iot"]),
    "50C7BF": ("TP-Link Technologies Co., Ltd.", ["network", "router", "switch", "ap", "iot"]),
    "E848B8": ("TP-Link Technologies Co., Ltd.", ["network", "router", "switch", "ap", "iot"]),
    "6032B1": ("TP-Link Technologies Co., Ltd.", ["network", "router", "switch", "ap", "iot"]),
    "74DA38": ("TP-Link Technologies Co., Ltd.", ["network", "router", "switch", "ap", "iot"]),

    # Netgear
    "00095B": ("NETGEAR", ["network", "router", "switch", "ap"]),
    "000FB5": ("NETGEAR", ["network", "router", "switch", "ap"]),
    "00146C": ("NETGEAR", ["network", "router", "switch", "ap"]),
    "00184D": ("NETGEAR", ["network", "router", "switch", "ap"]),
    "20E52A": ("NETGEAR", ["network", "router", "switch", "ap"]),
    "9C3DCF": ("NETGEAR", ["network", "router", "switch", "ap"]),

    # ASUSTek
    "000C6E": ("ASUSTek Computer Inc.", ["computer", "laptop", "router"]),
    "0011D8": ("ASUSTek Computer Inc.", ["computer", "laptop", "router"]),
    "0015F2": ("ASUSTek Computer Inc.", ["computer", "laptop", "router"]),
    "04D9F5": ("ASUSTek Computer Inc.", ["computer", "laptop", "router"]),
    "AC9E17": ("ASUSTek Computer Inc.", ["computer", "laptop", "router"]),

    # Espressif (IoT ESP8266 / ESP32)
    "18FE34": ("Espressif Inc.", ["iot"]),
    "240AC4": ("Espressif Inc.", ["iot"]),
    "30AEA4": ("Espressif Inc.", ["iot"]),
    "A4CF12": ("Espressif Inc.", ["iot"]),
    "84F3EB": ("Espressif Inc.", ["iot"]),
    "D8BFC0": ("Espressif Inc.", ["iot"]),

    # Raspberry Pi
    "B827EB": ("Raspberry Pi Foundation", ["computer", "iot", "server"]),
    "DCA632": ("Raspberry Pi Foundation", ["computer", "iot", "server"]),
    "E45F01": ("Raspberry Pi Foundation", ["computer", "iot", "server"]),
    "28CDC1": ("Raspberry Pi Foundation", ["computer", "iot", "server"]),

    # Printers: Canon, Epson, Brother, Xerox
    "000085": ("Canon Inc.", ["printer", "camera"]),
    "001E8F": ("Canon Inc.", ["printer", "camera"]),
    "180C7A": ("Canon Inc.", ["printer", "camera"]),
    "000048": ("Seiko Epson Corporation", ["printer"]),
    "002164": ("Seiko Epson Corporation", ["printer"]),
    "0026AB": ("Seiko Epson Corporation", ["printer"]),
    "008077": ("Brother Industries, Ltd.", ["printer"]),
    "001BA9": ("Brother Industries, Ltd.", ["printer"]),
    "0000AA": ("Xerox Corporation", ["printer"]),

    # Cameras: Hikvision, Dahua, Axis
    "4419B6": ("Hangzhou Hikvision Digital Technology", ["camera"]),
    "C05627": ("Hangzhou Hikvision Digital Technology", ["camera"]),
    "54C415": ("Hangzhou Hikvision Digital Technology", ["camera"]),
    "3C42FA": ("Zhejiang Dahua Technology Co., Ltd.", ["camera"]),
    "E0508B": ("Zhejiang Dahua Technology Co., Ltd.", ["camera"]),
    "9002A9": ("Zhejiang Dahua Technology Co., Ltd.", ["camera"]),
    "00408C": ("Axis Communications AB", ["camera"]),

    # Storage: Synology, QNAP
    "001132": ("Synology Incorporated", ["nas", "storage", "server"]),
    "00089B": ("QNAP Systems, Inc.", ["nas", "storage", "server"]),

    # Virtual Machines: VMware, Microsoft Hyper-V, VirtualBox
    "000569": ("VMware, Inc.", ["vm"]),
    "000C29": ("VMware, Inc.", ["vm"]),
    "001C14": ("VMware, Inc.", ["vm"]),
    "005056": ("VMware, Inc.", ["vm"]),
    "080027": ("PCS Systemtechnik GmbH (VirtualBox)", ["vm"]),
    "00155D": ("Microsoft Corporation (Hyper-V)", ["vm", "computer"]),

    # Smart TVs / Media / Consumer
    "00014A": ("Sony Corporation", ["tv", "media", "camera"]),
    "00041F": ("Sony Corporation", ["tv", "media", "camera"]),
    "FCF136": ("Sony Corporation", ["tv", "media", "camera"]),
    "0005C9": ("LG Electronics", ["tv", "media", "iot"]),
    "001C62": ("LG Electronics", ["tv", "media", "iot"]),
    "CC2D83": ("LG Electronics", ["tv", "media", "iot"]),
    "00FC8B": ("Amazon Technologies Inc.", ["media", "iot"]),
    "38F9D3": ("Amazon Technologies Inc.", ["media", "iot"]),
    "44650D": ("Amazon Technologies Inc.", ["media", "iot"]),
    "001A11": ("Google, Inc.", ["media", "phone", "iot"]),
    "3C5AB4": ("Google, Inc.", ["media", "phone", "iot"]),
    "F4F5DB": ("Google, Inc.", ["media", "phone", "iot"]),
}


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to uppercase colon-separated format."""
    if not mac:
        return ""
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(clean) == 12:
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))
    return mac.upper().strip()


def extract_oui(mac: str) -> str:
    """Extract standard 6-character hex OUI prefix from MAC address."""
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    return clean[:6] if len(clean) >= 6 else ""


def is_locally_administered_mac(mac: str) -> bool:
    """
    Check if the MAC address has the U/L (Universal/Local) bit set.
    Locally administered addresses are often randomized by iOS/Android
    or synthesized by scanners.
    """
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(clean) >= 2:
        try:
            byte0 = int(clean[:2], 16)
            return bool(byte0 & 0x02)
        except ValueError:
            pass
    return False


def is_synthetic_mac(mac: str) -> bool:
    """Check if MAC was synthetically generated by HorusShield socket scan."""
    norm = normalize_mac(mac)
    return norm.startswith("02:00:") or norm == "00:00:00:00:00:00"


def lookup_oui(mac: str) -> Dict[str, Any]:
    """
    Identify manufacturer from MAC address OUI.
    Returns:
        {
            "vendor": str,
            "manufacturer": str,
            "oui_prefix": str,
            "category_hints": List[str],
            "is_randomized": bool,
            "is_synthetic": bool,
            "reliable": bool
        }
    """
    normalized = normalize_mac(mac)
    oui = extract_oui(normalized)
    is_random = is_locally_administered_mac(normalized)
    is_synth = is_synthetic_mac(normalized)

    if not oui or is_synth:
        return {
            "vendor": "Unknown",
            "manufacturer": "Unknown",
            "oui_prefix": oui,
            "category_hints": [],
            "is_randomized": is_random,
            "is_synthetic": is_synth,
            "reliable": False,
        }

    # 1. Check curated local dictionary first
    if oui in _KNOWN_OUIS:
        mfg, hints = _KNOWN_OUIS[oui]
        return {
            "vendor": mfg,
            "manufacturer": mfg,
            "oui_prefix": oui,
            "category_hints": hints,
            "is_randomized": is_random,
            "is_synthetic": False,
            "reliable": True,
        }

    # 2. Try mac_vendor_lookup if installed
    try:
        from mac_vendor_lookup import MacLookup
        raw_vendor = MacLookup().lookup(normalized)
        if raw_vendor and raw_vendor.strip():
            cleaned_vendor = raw_vendor.strip()
            hints = _infer_hints_from_vendor_name(cleaned_vendor)
            return {
                "vendor": cleaned_vendor,
                "manufacturer": cleaned_vendor,
                "oui_prefix": oui,
                "category_hints": hints,
                "is_randomized": is_random,
                "is_synthetic": False,
                "reliable": True,
            }
    except Exception:
        pass

    return {
        "vendor": "Unknown",
        "manufacturer": "Unknown",
        "oui_prefix": oui,
        "category_hints": [],
        "is_randomized": is_random,
        "is_synthetic": False,
        "reliable": False,
    }


def _infer_hints_from_vendor_name(vendor: str) -> List[str]:
    """Infer high-level category hints from manufacturer string."""
    v = vendor.lower()
    hints = []
    if any(k in v for k in ["apple"]):
        hints.extend(["phone", "tablet", "computer", "media"])
    elif any(k in v for k in ["samsung"]):
        hints.extend(["phone", "tablet", "tv", "iot"])
    elif any(k in v for k in ["huawei"]):
        hints.extend(["phone", "network", "router", "laptop"])
    elif any(k in v for k in ["xiaomi"]):
        hints.extend(["phone", "tablet", "tv", "iot"])
    elif any(k in v for k in ["hp", "hewlett"]):
        hints.extend(["computer", "laptop", "printer", "server"])
    elif any(k in v for k in ["dell"]):
        hints.extend(["computer", "laptop", "server"])
    elif any(k in v for k in ["lenovo"]):
        hints.extend(["computer", "laptop", "tablet"])
    elif any(k in v for k in ["cisco", "tp-link", "netgear", "d-link", "ubiquiti", "mikrotik"]):
        hints.extend(["network", "router", "switch", "ap"])
    elif any(k in v for k in ["canon", "epson", "brother", "xerox"]):
        hints.extend(["printer"])
    elif any(k in v for k in ["hikvision", "dahua", "axis", "foscam"]):
        hints.extend(["camera"])
    elif any(k in v for k in ["synology", "qnap", "asustor"]):
        hints.extend(["nas", "storage", "server"])
    elif any(k in v for k in ["vmware", "virtualbox"]):
        hints.extend(["vm"])
    elif any(k in v for k in ["espressif", "tuya", "sonoff"]):
        hints.extend(["iot"])
    return hints
