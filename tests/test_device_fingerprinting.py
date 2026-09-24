"""
Unit Tests for HorusShield 2.0 Device Identification & Fingerprinting Engine
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Validates multi-signal classification, anti-false-positive guarantees,
OUI identification, hostname analysis, DHCP / mDNS / SSDP integration,
caching, and API endpoints.
"""

import json
import pytest

from device_fingerprinting.models import (
    DEVICE_TYPE_WINDOWS_PC,
    DEVICE_TYPE_WINDOWS_LAPTOP,
    DEVICE_TYPE_IPHONE,
    DEVICE_TYPE_IPAD,
    DEVICE_TYPE_ANDROID_PHONE,
    DEVICE_TYPE_ANDROID_TABLET,
    DEVICE_TYPE_ROUTER,
    DEVICE_TYPE_GATEWAY,
    DEVICE_TYPE_PRINTER,
    DEVICE_TYPE_CAMERA,
    DEVICE_TYPE_UNKNOWN,
)
from device_fingerprinting.classifier import device_classifier
from device_fingerprinting.oui import (
    lookup_oui,
    is_locally_administered_mac,
    normalize_mac,
)
from device_fingerprinting.engine import fingerprint_engine


# ==============================================================================
# 8 Core Required Specification Tests
# ==============================================================================

def test_case_1_hp_desktop_windows_pc():
    """
    Test 1: Vendor = Hewlett Packard, Hostname = DESKTOP-8K3N91A
    Expected: Windows PC / Computer, OS = Windows.
    """
    res = device_classifier.classify(
        ip="192.168.1.104",
        mac="3C:D9:2B:AA:BB:CC",
        hostname="DESKTOP-8K3N91A",
        oui_info={"vendor": "Hewlett Packard", "reliable": True},
        service_info={"open_ports": [135, 445], "has_smb": True},
    )
    assert res.device_type == DEVICE_TYPE_WINDOWS_PC
    assert res.os == "Windows"
    assert "Hewlett Packard" in res.vendor or "HP" in res.vendor
    assert res.confidence >= 50
    assert any("DESKTOP-" in ev for ev in res.evidence)


def test_case_2_apple_iphone():
    """
    Test 2: Vendor = Apple, Hostname = iPhone / iPhone-de-Sarah
    Expected: iPhone, OS = iOS, Manufacturer = Apple.
    """
    res = device_classifier.classify(
        ip="192.168.1.115",
        mac="F0:18:98:12:34:56",
        hostname="iPhone-de-Sarah",
        oui_info={"vendor": "Apple, Inc.", "reliable": True},
        mdns_services=["_airplay._tcp"],
    )
    assert res.device_type == DEVICE_TYPE_IPHONE
    assert res.os == "iOS"
    assert "Apple" in res.vendor
    assert res.confidence >= 50
    assert any("iPhone" in ev for ev in res.evidence)


def test_case_3_samsung_galaxy_tablet():
    """
    Test 3: Vendor = Samsung, Hostname = SM-X700 (Galaxy Tab S8)
    Expected: Android Tablet, OS = Android.
    """
    res = device_classifier.classify(
        ip="192.168.1.120",
        mac="AC:5F:3E:44:55:66",
        hostname="SM-X700",
        oui_info={"vendor": "Samsung Electronics", "reliable": True},
    )
    assert res.device_type == DEVICE_TYPE_ANDROID_TABLET
    assert res.os == "Android"
    assert "Samsung" in res.vendor
    assert res.model == "SM-X700"
    assert any("Samsung Galaxy tablet" in ev for ev in res.evidence)


def test_case_4_gateway_dhcp_router():
    """
    Test 4: Gateway IP + DHCP server behavior
    Expected: Router / Network Gateway.
    """
    res = device_classifier.classify(
        ip="192.168.1.1",
        mac="00:14:D1:AA:BB:CC",
        hostname="router.home",
        oui_info={"vendor": "Trendnet", "reliable": True},
        is_gateway=True,
        dhcp_info={
            "evidence": ["Active DHCP Server on port 67"],
            "confidence_boost": 25,
        },
        service_info={"open_ports": [53, 80], "has_gateway_services": True},
    )
    assert res.device_type in (DEVICE_TYPE_ROUTER, DEVICE_TYPE_GATEWAY)
    assert res.is_gateway is True
    assert res.confidence >= 60
    assert any("gateway" in ev.lower() for ev in res.evidence)


def test_case_5_ipp_printer():
    """
    Test 5: IPP (Port 631 / 9100) + printer metadata / mDNS
    Expected: Printer.
    """
    res = device_classifier.classify(
        ip="192.168.1.55",
        mac="00:00:85:11:22:33",
        hostname="Canon-MF644C",
        oui_info={"vendor": "Canon", "reliable": True},
        mdns_services=["_ipp._tcp", "_printer._tcp"],
        service_info={
            "open_ports": [631, 9100],
            "has_printer_ports": True,
        },
    )
    assert res.device_type == DEVICE_TYPE_PRINTER
    assert res.confidence >= 70
    assert any("printer" in ev.lower() or "ipp" in ev.lower() for ev in res.evidence)


def test_case_6_rtsp_camera():
    """
    Test 6: RTSP (Port 554) + camera metadata / Hikvision OUI
    Expected: Camera / IP Camera.
    """
    res = device_classifier.classify(
        ip="192.168.1.80",
        mac="44:19:B6:11:22:33",
        hostname="HIK-IPCam-Front",
        oui_info={"vendor": "Hikvision", "reliable": True},
        service_info={
            "open_ports": [554, 8000],
            "has_camera_ports": True,
        },
    )
    assert res.device_type == DEVICE_TYPE_CAMERA
    assert res.confidence >= 60
    assert any("camera" in ev.lower() or "rtsp" in ev.lower() for ev in res.evidence)


def test_case_7_unknown_random_mac():
    """
    Test 7: Unknown vendor + randomized / locally administered MAC + no hostname
    Expected: Unknown Device, confidence <= 30%.
    """
    # Bit 1 of first byte set = locally administered / randomized
    mac = "DA:A1:19:12:34:56"
    assert is_locally_administered_mac(mac) is True

    oui = lookup_oui(mac)
    assert oui["is_randomized"] is True

    res = device_classifier.classify(
        ip="192.168.1.200",
        mac=mac,
        hostname="",
        oui_info=oui,
    )
    assert res.device_type == DEVICE_TYPE_UNKNOWN
    assert res.confidence <= 30
    assert any("random" in ev.lower() or "mac" in ev.lower() for ev in res.evidence)


def test_case_8_conflicting_fingerprints():
    """
    Test 8: Conflicting fingerprints (Apple OUI + Windows Server hostname)
    Expected: Low confidence, honesty over guessing, conflict recorded.
    """
    res = device_classifier.classify(
        ip="192.168.1.199",
        mac="00:03:93:11:22:33",  # Apple OUI
        hostname="WIN-SRV-2019-DC",
        oui_info={"vendor": "Apple, Inc.", "reliable": True},
    )
    # The engine should penalize confidence and detect conflict
    assert res.confidence <= 35
    assert len(res.raw_signals.get("conflicts", [])) > 0 or any("conflict" in ev.lower() for ev in res.evidence)


# ==============================================================================
# Anti-False-Positive Guarantee Tests
# ==============================================================================

def test_apple_alone_does_not_become_iphone():
    """
    Manufacturer ≠ Device Type.
    Apple MAC alone with no hostname or services must NOT automatically become iPhone.
    """
    res = device_classifier.classify(
        ip="192.168.1.52",
        mac="00:17:F2:11:22:33",
        hostname="",
        oui_info={"vendor": "Apple, Inc.", "reliable": True},
    )
    # Without corroboration, it must remain honest (Unknown Device or generic Apple)
    assert res.device_type == DEVICE_TYPE_UNKNOWN
    assert res.confidence < 40


def test_samsung_alone_does_not_become_phone():
    """Samsung OUI alone must NOT blindly classify as Android Phone."""
    res = device_classifier.classify(
        ip="192.168.1.53",
        mac="00:07:AB:11:22:33",
        hostname="",
        oui_info={"vendor": "Samsung Electronics", "reliable": True},
    )
    assert res.device_type == DEVICE_TYPE_UNKNOWN


def test_hp_alone_does_not_become_laptop():
    """HP OUI alone must NOT blindly classify as Laptop without evidence."""
    res = device_classifier.classify(
        ip="192.168.1.54",
        mac="00:80:5F:11:22:33",
        hostname="",
        oui_info={"vendor": "Hewlett Packard", "reliable": True},
    )
    assert res.device_type == DEVICE_TYPE_UNKNOWN


# ==============================================================================
# OUI Engine Tests
# ==============================================================================

def test_oui_normalization_and_lookup():
    """Test MAC normalization and known vendor lookups."""
    # Cisco
    assert "Cisco" in lookup_oui("00-01-42-AA-BB-CC")["vendor"]
    # Dell
    assert "Dell" in lookup_oui("00:14:22:11:22:33")["vendor"]
    # Raspberry Pi
    assert "Raspberry Pi" in lookup_oui("b8:27:eb:11:22:33")["vendor"]


# ==============================================================================
# Engine Caching & Integration Tests
# ==============================================================================

def test_fingerprint_engine_caching():
    """Test that fingerprint results are cached by MAC and expire properly."""
    mac = "00:14:22:99:88:77"
    fingerprint_engine.clear_cache()

    fp1 = fingerprint_engine.fingerprint_device(
        ip="192.168.1.188",
        mac=mac,
        hostname="DELL-OPTIPLEX",
        background_enrich=False,
    )
    assert fp1.mac == mac

    # Second call should hit memory cache
    fp2 = fingerprint_engine.fingerprint_device(
        ip="192.168.1.188",
        mac=mac,
        hostname="DELL-OPTIPLEX",
        background_enrich=False,
    )
    assert fp2.cached is True

    # Force refresh bypasses cache
    fp3 = fingerprint_engine.fingerprint_device(
        ip="192.168.1.188",
        mac=mac,
        hostname="DELL-OPTIPLEX",
        force_refresh=True,
        background_enrich=False,
    )
    assert fp3.cached is False


# ==============================================================================
# Flask API Route Integration Tests
# ==============================================================================

def test_devices_api_enriched_response(flask_app, client, auth_headers):
    """Test that GET /api/devices/ returns enriched device structures."""
    from database.db_manager import db

    test_mac = "70:85:C2:55:66:77"
    db.add_device(
        mac_address=test_mac,
        ip_address="192.168.1.99",
        hostname="DESKTOP-TESTER",
        vendor="Hewlett Packard",
        device_type="Windows PC",
        manufacturer="Hewlett Packard",
        model="Pavilion",
        confidence=85,
    )

    resp = client.get(
        "/api/devices/",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)

    target = next((d for d in data if d.get("mac_address") == test_mac), None)
    assert target is not None
    assert target["device_type"] == "Windows PC"
    assert "manufacturer" in target
    assert "confidence" in target
    assert "icon" in target
