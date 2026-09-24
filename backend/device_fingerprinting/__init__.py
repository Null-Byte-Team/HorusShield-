"""
HorusShield 2.0 — Device Fingerprinting Package
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Centralized device identification, classification, and fingerprinting engine.
"""

from device_fingerprinting.models import (
    ALL_DEVICE_TYPES,
    DEVICE_TYPE_ACCESS_POINT,
    DEVICE_TYPE_ANDROID_PHONE,
    DEVICE_TYPE_ANDROID_TABLET,
    DEVICE_TYPE_CAMERA,
    DEVICE_TYPE_GATEWAY,
    DEVICE_TYPE_ICONS,
    DEVICE_TYPE_IOT,
    DEVICE_TYPE_IPAD,
    DEVICE_TYPE_IPHONE,
    DEVICE_TYPE_LINUX_PC,
    DEVICE_TYPE_LINUX_SERVER,
    DEVICE_TYPE_MACOS,
    DEVICE_TYPE_NAS,
    DEVICE_TYPE_NETWORK_DEVICE,
    DEVICE_TYPE_PRINTER,
    DEVICE_TYPE_ROUTER,
    DEVICE_TYPE_SERVER,
    DEVICE_TYPE_SMART_TV,
    DEVICE_TYPE_SWITCH,
    DEVICE_TYPE_UNKNOWN,
    DEVICE_TYPE_VM,
    DEVICE_TYPE_WINDOWS_LAPTOP,
    DEVICE_TYPE_WINDOWS_PC,
    DeviceFingerprintResult,
)
from device_fingerprinting.oui import lookup_oui, normalize_mac
from device_fingerprinting.dhcp import dhcp_fingerprinter
from device_fingerprinting.mdns import mdns_discoverer
from device_fingerprinting.ssdp import ssdp_discoverer
from device_fingerprinting.services import service_fingerprinter
from device_fingerprinting.classifier import device_classifier, DeviceClassifier
from device_fingerprinting.engine import fingerprint_engine, DeviceFingerprintEngine

__all__ = [
    "fingerprint_engine",
    "DeviceFingerprintEngine",
    "DeviceFingerprintResult",
    "device_classifier",
    "DeviceClassifier",
    "lookup_oui",
    "normalize_mac",
    "dhcp_fingerprinter",
    "mdns_discoverer",
    "ssdp_discoverer",
    "service_fingerprinter",
    "ALL_DEVICE_TYPES",
    "DEVICE_TYPE_ICONS",
    "DEVICE_TYPE_WINDOWS_PC",
    "DEVICE_TYPE_WINDOWS_LAPTOP",
    "DEVICE_TYPE_LINUX_PC",
    "DEVICE_TYPE_LINUX_SERVER",
    "DEVICE_TYPE_MACOS",
    "DEVICE_TYPE_IPHONE",
    "DEVICE_TYPE_IPAD",
    "DEVICE_TYPE_ANDROID_PHONE",
    "DEVICE_TYPE_ANDROID_TABLET",
    "DEVICE_TYPE_SMART_TV",
    "DEVICE_TYPE_PRINTER",
    "DEVICE_TYPE_ROUTER",
    "DEVICE_TYPE_SWITCH",
    "DEVICE_TYPE_ACCESS_POINT",
    "DEVICE_TYPE_GATEWAY",
    "DEVICE_TYPE_IOT",
    "DEVICE_TYPE_CAMERA",
    "DEVICE_TYPE_NAS",
    "DEVICE_TYPE_SERVER",
    "DEVICE_TYPE_VM",
    "DEVICE_TYPE_NETWORK_DEVICE",
    "DEVICE_TYPE_UNKNOWN",
]
