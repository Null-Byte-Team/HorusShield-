"""Tests for authentication query param, vscanner tools check, and mesh topology."""
import pytest
from database.db_manager import db


def test_token_in_query_param_authenticates_successfully(client, auth_headers):
    """Verify that passing ?token=<token> in the query string authenticates correctly."""
    token = auth_headers["Authorization"].split(" ")[1]

    # Without token
    resp_no_token = client.get("/api/vscanner/history")
    assert resp_no_token.status_code == 401
    assert resp_no_token.get_json().get("error") == "Authentication required"

    # With query param token
    resp_with_token = client.get(f"/api/vscanner/history?token={token}")
    assert resp_with_token.status_code == 200
    assert isinstance(resp_with_token.get_json(), list)


def test_vscanner_tools_endpoint(client, auth_headers):
    """Verify that /api/vscanner/tools returns tool availability status."""
    token = auth_headers["Authorization"].split(" ")[1]
    resp = client.get(f"/api/vscanner/tools?token={token}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "tools" in data
    assert "nmap" in data["tools"]
    assert "zap" in data["tools"]
    assert "nikto" in data["tools"]
    assert isinstance(data["tools"]["nmap"], bool)
    assert isinstance(data["tools"]["zap"], bool)
    assert isinstance(data["tools"]["nikto"], bool)


def test_mesh_topology_returns_valid_structure(client, auth_headers):
    """Verify that /api/mesh/topology returns valid nodes and links arrays."""
    token = auth_headers["Authorization"].split(" ")[1]
    resp = client.get(f"/api/mesh/topology?token={token}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "nodes" in data
    assert "links" in data
    assert isinstance(data["nodes"], list)
    assert isinstance(data["links"], list)
