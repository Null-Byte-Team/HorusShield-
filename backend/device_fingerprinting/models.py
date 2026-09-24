"""
HorusShield 2.0 — Device Fingerprinting Models & Constants
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Standard device type taxonomy, data structures, and evidence representations.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── Canonical Device Types ──
DEVICE_TYPE_WINDOWS_PC = "Windows PC"
DEVICE_TYPE_WINDOWS_LAPTOP = "Windows Laptop"
DEVICE_TYPE_LINUX_PC = "Linux PC"
DEVICE_TYPE_LINUX_SERVER = "Linux Server"
DEVICE_TYPE_MACOS = "macOS Computer"
DEVICE_TYPE_IPHONE = "iPhone"
DEVICE_TYPE_IPAD = "iPad"
DEVICE_TYPE_ANDROID_PHONE = "Android Phone"
DEVICE_TYPE_ANDROID_TABLET = "Android Tablet"
DEVICE_TYPE_SMART_TV = "Smart TV"
DEVICE_TYPE_PRINTER = "Printer"
DEVICE_TYPE_ROUTER = "Router"
DEVICE_TYPE_SWITCH = "Switch"
DEVICE_TYPE_ACCESS_POINT = "Access Point"
DEVICE_TYPE_GATEWAY = "Network Gateway"
DEVICE_TYPE_IOT = "IoT Device"
DEVICE_TYPE_CAMERA = "Camera / IP Camera"
DEVICE_TYPE_NAS = "NAS / Storage"
DEVICE_TYPE_SERVER = "Server"
DEVICE_TYPE_VM = "Virtual Machine"
DEVICE_TYPE_NETWORK_DEVICE = "Network Device"
DEVICE_TYPE_UNKNOWN = "Unknown Device"

ALL_DEVICE_TYPES = [
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
]

# Map device types to user-friendly UI icons
DEVICE_TYPE_ICONS: Dict[str, str] = {
    DEVICE_TYPE_WINDOWS_PC: "💻",
    DEVICE_TYPE_WINDOWS_LAPTOP: "💻",
    DEVICE_TYPE_LINUX_PC: "💻",
    DEVICE_TYPE_LINUX_SERVER: "🖥️",
    DEVICE_TYPE_MACOS: "💻",
    DEVICE_TYPE_IPHONE: "📱",
    DEVICE_TYPE_IPAD: "📱",
    DEVICE_TYPE_ANDROID_PHONE: "📱",
    DEVICE_TYPE_ANDROID_TABLET: "📱",
    DEVICE_TYPE_SMART_TV: "📺",
    DEVICE_TYPE_PRINTER: "🖨️",
    DEVICE_TYPE_ROUTER: "📡",
    DEVICE_TYPE_SWITCH: "🔀",
    DEVICE_TYPE_ACCESS_POINT: "📶",
    DEVICE_TYPE_GATEWAY: "🌐",
    DEVICE_TYPE_IOT: "🔌",
    DEVICE_TYPE_CAMERA: "📷",
    DEVICE_TYPE_NAS: "🗄️",
    DEVICE_TYPE_SERVER: "🖥️",
    DEVICE_TYPE_VM: "🔲",
    DEVICE_TYPE_NETWORK_DEVICE: "🌐",
    DEVICE_TYPE_UNKNOWN: "❓",
}


@dataclass
class DeviceFingerprintResult:
    """Standard result structure produced by the Device Fingerprinting Engine."""
    ip: str
    mac: str
    hostname: str = "Unknown"
    vendor: str = "Unknown"
    manufacturer: str = "Unknown"
    device_type: str = DEVICE_TYPE_UNKNOWN
    model: Optional[str] = None
    os: str = "Unknown"
    confidence: int = 0
    evidence: List[str] = field(default_factory=list)
    services: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    is_gateway: bool = False
    status: str = "online"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    raw_signals: Dict[str, Any] = field(default_factory=dict)
    cached: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary for API and DB."""
        return {
            "ip": self.ip,
            "ip_address": self.ip,
            "mac": self.mac,
            "mac_address": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "manufacturer": self.manufacturer or self.vendor,
            "device_type": self.device_type,
            "model": self.model,
            "os": self.os,
            "confidence": max(0, min(100, int(self.confidence))),
            "evidence": list(self.evidence),
            "services": list(self.services),
            "protocols": list(self.protocols),
            "is_gateway": bool(self.is_gateway),
            "status": self.status,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "icon": DEVICE_TYPE_ICONS.get(self.device_type, "❓"),
            "fingerprint": self.raw_signals,
        }
