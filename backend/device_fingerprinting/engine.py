"""
HorusShield 2.0 — Centralized Device Fingerprinting Engine
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Coordinates discovery modules (OUI, Hostname, DHCP, mDNS, SSDP, Services),
manages thread-safe MAC-keyed result caching with expiration,
and runs deep network investigations asynchronously without blocking the UI.
"""

from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple


from device_fingerprinting.models import (
    DEVICE_TYPE_UNKNOWN,
    DeviceFingerprintResult,
)
from device_fingerprinting.oui import lookup_oui
from device_fingerprinting.dhcp import dhcp_fingerprinter
from device_fingerprinting.mdns import mdns_discoverer
from device_fingerprinting.ssdp import ssdp_discoverer
from device_fingerprinting.services import service_fingerprinter
from device_fingerprinting.classifier import device_classifier
from utils.logger import get_logger

logger = get_logger("fingerprint_engine", "device")

DEFAULT_CACHE_TTL = 3600.0  # 1 hour


class DeviceFingerprintEngine:
    """Central orchestrator for HorusShield device identification."""

    _instance: Optional["DeviceFingerprintEngine"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "DeviceFingerprintEngine":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        # Cache: MAC (upper) -> (DeviceFingerprintResult, timestamp)
        self._cache: Dict[str, Tuple[DeviceFingerprintResult, float]] = {}
        self._cache_lock = threading.Lock()
        # Set of MACs currently queued for deep background investigation
        self._pending_tasks: Set[str] = set()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="DevFingerprint")
        self._socketio = None
        self._initialized = True
        logger.info("Device Fingerprinting Engine initialized")

    def set_socketio(self, socketio: Any) -> None:
        """Bind socketio instance for real-time WebSocket updates."""
        self._socketio = socketio

    def get_cached(self, mac: str) -> Optional[DeviceFingerprintResult]:
        """Return cached result if present and not expired."""
        if not mac:
            return None
        mac_key = mac.upper()
        with self._cache_lock:
            entry = self._cache.get(mac_key)
            if entry:
                result, ts = entry
                if time.time() - ts < DEFAULT_CACHE_TTL:
                    return result
        return None

    def fingerprint_device(
        self,
        ip: str,
        mac: str,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        is_gateway: bool = False,
        open_ports: Optional[List[int]] = None,
        force_refresh: bool = False,
        background_enrich: bool = True,
    ) -> DeviceFingerprintResult:
        """
        Identify a device using all available evidence.
        Returns immediate fast-path result and queues non-blocking deep probe if needed.
        """
        mac_clean = (mac or "").upper()

        if not force_refresh:
            cached = self.get_cached(mac_clean)
            if cached:
                cached.cached = True
                return cached

        # Fast in-memory / local signals
        oui_info = lookup_oui(mac_clean)
        # If caller passed a known vendor, prefer it if OUI was unknown
        if vendor and vendor != "Unknown" and oui_info.get("vendor") == "Unknown":
            oui_info["vendor"] = vendor
            oui_info["manufacturer"] = vendor

        dhcp_info = dhcp_fingerprinter.get_fingerprint(mac_clean)
        mdns_svcs = mdns_discoverer.get_services_for_ip(ip)
        mdns_name = mdns_discoverer.get_name_for_ip(ip)
        ssdp_info = ssdp_discoverer.get_ssdp_for_ip(ip)

        service_data = {
            "open_ports": open_ports or [],
            "has_printer_ports": any(p in (open_ports or []) for p in (631, 9100)),
            "has_camera_ports": 554 in (open_ports or []),
            "has_smb": any(p in (open_ports or []) for p in (445, 139)),
            "has_rdp": 3389 in (open_ports or []),
            "has_dns": 53 in (open_ports or []),
            "has_gateway_services": is_gateway or (53 in (open_ports or []) and 80 in (open_ports or [])),
        }

        # Produce immediate classification
        result = device_classifier.classify(
            ip=ip,
            mac=mac_clean,
            hostname=hostname,
            oui_info=oui_info,
            dhcp_info=dhcp_info,
            mdns_services=mdns_svcs,
            mdns_name=mdns_name,
            ssdp_info=ssdp_info,
            service_info=service_data,
            is_gateway=is_gateway,
        )

        with self._cache_lock:
            self._cache[mac_clean] = (result, time.time())

        # Queue deep background probe if needed and not already pending
        if background_enrich and not mac_clean.startswith("02:00:"):
            with self._cache_lock:
                should_queue = mac_clean not in self._pending_tasks
                if should_queue:
                    self._pending_tasks.add(mac_clean)

            if should_queue:
                self._executor.submit(
                    self._async_deep_probe,
                    ip,
                    mac_clean,
                    hostname,
                    is_gateway,
                    open_ports,
                )

        return result

    def _async_deep_probe(
        self,
        ip: str,
        mac: str,
        hostname: Optional[str],
        is_gateway: bool,
        initial_ports: Optional[List[int]],
    ) -> None:
        """Asynchronously probe mDNS, SSDP, and services then update DB & WebSocket."""
        try:
            # Trigger quick sweeps if needed
            mdns_discoverer.trigger_sweep(timeout_sec=0.4)
            ssdp_discoverer.trigger_sweep(timeout_sec=0.5)

            # Probe diagnostic ports and banners
            service_info = service_fingerprinter.probe_services(ip, given_ports=initial_ports)

            # Re-read discovery caches
            oui_info = lookup_oui(mac)
            dhcp_info = dhcp_fingerprinter.get_fingerprint(mac)
            mdns_svcs = mdns_discoverer.get_services_for_ip(ip)
            mdns_name = mdns_discoverer.get_name_for_ip(ip)
            ssdp_info = ssdp_discoverer.get_ssdp_for_ip(ip)

            enriched = device_classifier.classify(
                ip=ip,
                mac=mac,
                hostname=hostname,
                oui_info=oui_info,
                dhcp_info=dhcp_info,
                mdns_services=mdns_svcs,
                mdns_name=mdns_name,
                ssdp_info=ssdp_info,
                service_info=service_info,
                is_gateway=is_gateway,
            )

            # Update cache
            with self._cache_lock:
                self._cache[mac] = (enriched, time.time())

            # Update Database
            self._persist_fingerprint_to_db(enriched)

            # Emit real-time WebSocket update
            if self._socketio:
                try:
                    self._socketio.emit("device_updated", enriched.to_dict())
                except Exception as e:
                    logger.debug(f"WebSocket emit notice: {e}")

            logger.info(
                f"Fingerprint enriched: {ip} ({mac}) → {enriched.device_type} "
                f"[{enriched.confidence}%] ({enriched.manufacturer})"
            )

        except Exception as e:
            logger.debug(f"Deep probe error for {ip}: {e}")
        finally:
            with self._cache_lock:
                self._pending_tasks.discard(mac)

    def _persist_fingerprint_to_db(self, res: DeviceFingerprintResult) -> None:
        """Update existing device row in SQLite with enriched fingerprint values."""
        try:
            from database.db_manager import db
            device = db.get_device(mac_address=res.mac)
            if device:
                db.update_device(
                    device["id"],
                    device_type=res.device_type,
                    vendor=res.manufacturer or res.vendor,
                    manufacturer=res.manufacturer,
                    model=res.model or "",
                    os_info=res.os,
                    confidence=res.confidence,
                    evidence=json.dumps(res.evidence),
                    fingerprint=json.dumps(res.raw_signals),
                    open_ports=json.dumps(res.services),
                )
        except Exception as e:
            logger.debug(f"DB persist fingerprint error: {e}")

    def enrich_devices(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich a list of device dictionaries with current fingerprint data."""
        enriched_list = []
        for dev in devices:
            mac = dev.get("mac_address") or dev.get("mac", "")
            ip = dev.get("ip_address") or dev.get("ip", "")
            host = dev.get("hostname")
            vendor = dev.get("vendor")
            is_gw = bool(dev.get("is_gateway", False))
            ports = dev.get("open_ports", [])
            if isinstance(ports, str):
                try:
                    ports = json.loads(ports)
                except Exception:
                    ports = []

            fp = self.fingerprint_device(
                ip=ip,
                mac=mac,
                hostname=host,
                vendor=vendor,
                is_gateway=is_gw,
                open_ports=ports,
                background_enrich=False,  # Don't swarm during list renders
            )

            d = dict(dev)
            d.update({
                "device_type": fp.device_type,
                "vendor": fp.manufacturer or fp.vendor,
                "manufacturer": fp.manufacturer,
                "model": fp.model or dev.get("model"),
                "os": fp.os,
                "os_info": fp.os,
                "confidence": fp.confidence,
                "evidence": fp.evidence,
                "icon": fp.to_dict().get("icon", "❓"),
            })
            enriched_list.append(d)
        return enriched_list

    def clear_cache(self, mac: Optional[str] = None) -> None:
        """Clear cache for specific MAC or all cached fingerprints."""
        with self._cache_lock:
            if mac:
                self._cache.pop(mac.upper(), None)
            else:
                self._cache.clear()


fingerprint_engine = DeviceFingerprintEngine()
