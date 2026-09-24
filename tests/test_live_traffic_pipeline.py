"""Tests for live traffic endpoints, packet logs, protocol split, and attack map."""
import pytest


def test_live_traffic_endpoint(client, auth_headers):
    resp = client.get("/api/traffic/live", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "packets_per_sec" in data
    assert "active_connections" in data
    assert "protocol_distribution" in data
    assert "bandwidth_mbps" in data
    assert "download_mbps" in data
    assert "upload_mbps" in data


def test_traffic_packets_endpoint(client, auth_headers):
    resp = client.get("/api/traffic/packets?limit=25", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)


def test_traffic_protocols_endpoint(client, auth_headers):
    resp = client.get("/api/traffic/protocols", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "tcp" in data
    assert "udp" in data
    assert "icmp" in data
    assert "other" in data
    assert "total" in data


def test_attacks_threat_map_endpoint(client, auth_headers):
    resp = client.get("/api/attacks/threat-map", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)


def test_dashboard_stats_endpoint(client, auth_headers):
    resp = client.get("/api/dashboard/stats", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "devices" in data
    assert "active_attacks" in data
    assert "traffic" in data
