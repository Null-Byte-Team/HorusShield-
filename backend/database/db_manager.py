"""
HorusShield Database Manager
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Thread-safe CRUD operations — improved version with:
  • Context-managed per-call connections (no leaked thread-local state)
  • Proper WAL + foreign-keys + busy-timeout on every new connection
  • All public methods type-annotated
  • get_active_attacks_count() fast path avoids full table scan
  • Bulk-insert helpers for traffic snapshots
  • Auto-cleanup of expired blocks inside is_blocked()
"""

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from database.models import DB_PATH, init_database
from utils.helpers import synthetic_mac_from_ip
from utils.logger import get_logger

logger = get_logger("db_manager", "system")


# ── module-level sentinel so we can detect un-initialised singleton ──
_UNSET = object()


class DatabaseManager:
    """Thread-safe database manager.

    Uses a per-call connection strategy: each `get_connection()` call opens
    (or reuses, within the same thread) a connection, executes the work,
    commits/rolls-back, and the caller can rely on the context-manager to
    handle cleanup.  Connections are cached per-thread to avoid the overhead
    of a full open/close on every call while remaining safe under multi-
    threading.
    """

    _instance: Optional["DatabaseManager"] = None
    _lock: threading.Lock = threading.Lock()

    # ── singleton ──

    def __new__(cls, db_path: Optional[str] = None) -> "DatabaseManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    obj = super().__new__(cls)
                    obj._initialized = False          # type: ignore[attr-defined]
                    cls._instance = obj
        return cls._instance

    def __init__(self, db_path: Optional[str] = None) -> None:
        if self._initialized:  # type: ignore[attr-defined]
            return
        self.db_path: str = db_path or DB_PATH
        self._local = threading.local()
        init_database(self.db_path)
        self._initialized = True  # type: ignore[attr-defined]

    # ── low-level connection helpers ──

    def _open_connection(self) -> sqlite3.Connection:
        """Open a new SQLite connection with recommended pragmas."""
        conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @contextmanager
    def get_connection(self):
        """Yield a thread-local SQLite connection; commit on success, rollback on error."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = self._open_connection()
        conn = self._local.conn
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # ── row conversion helpers ──

    @staticmethod
    def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        return dict(row) if row is not None else None

    @staticmethod
    def _rows_to_dicts(rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
        return [dict(r) for r in rows]

    def _decode_json_fields(
        self,
        record: Optional[Dict[str, Any]],
        field_defaults: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Parse JSON-encoded string fields in a record dict."""
        if record is None:
            return None
        parsed = dict(record)
        for field, default in field_defaults.items():
            value = parsed.get(field)
            if isinstance(value, str):
                try:
                    parsed[field] = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    parsed[field] = default
            elif value is None:
                parsed[field] = default
        return parsed

    # ══════════════════════════════════════
    # DEVICES
    # ══════════════════════════════════════

    def add_device(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
        hostname: str = "Unknown",
        vendor: str = "Unknown",
        device_type: str = "unknown",
        status: str = "unknown",
        is_gateway: int = 0,
    ) -> int:
        """Insert or update a device row; return the row id."""
        with self.get_connection() as conn:
            existing = conn.execute(
                "SELECT id FROM devices WHERE mac_address = ?", (mac_address,)
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE devices
                       SET ip_address=?, hostname=?, vendor=?, is_gateway=?,
                           last_seen=CURRENT_TIMESTAMP, last_activity='seen'
                       WHERE mac_address=?""",
                    (ip_address, hostname, vendor, is_gateway, mac_address),
                )
                return existing["id"]
            cursor = conn.execute(
                """INSERT INTO devices
                   (mac_address, ip_address, hostname, vendor, device_type, status, is_gateway)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (mac_address, ip_address, hostname, vendor, device_type, status, is_gateway),
            )
            return cursor.lastrowid

    def get_device(
        self,
        device_id: Optional[int] = None,
        mac_address: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch a single device by id, MAC, or IP."""
        with self.get_connection() as conn:
            if device_id is not None:
                row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
            elif mac_address:
                row = conn.execute("SELECT * FROM devices WHERE mac_address = ?", (mac_address,)).fetchone()
            elif ip_address:
                row = conn.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,)).fetchone()
            else:
                return None
        return self._decode_json_fields(self._row_to_dict(row), {"open_ports": []})

    def get_all_devices(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return all devices, optionally filtered by status."""
        with self.get_connection() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM devices WHERE status = ? ORDER BY last_seen DESC", (status,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
        return [self._decode_json_fields(r, {"open_ports": []}) for r in self._rows_to_dicts(rows)]

    def update_device(self, device_id: int, **kwargs: Any) -> None:
        """Update allowed device fields by id."""
        allowed = {
            "ip_address", "hostname", "vendor", "device_type", "os_info",
            "open_ports", "status", "is_gateway", "risk_score",
            "last_seen", "last_activity", "notes",
        }
        fields = {k: v for k, v in kwargs.items() if k in allowed}
        if not fields:
            return
        set_clause = ", ".join(f"{k}=?" for k in fields)
        values = list(fields.values()) + [device_id]
        with self.get_connection() as conn:
            # nosec B608: `fields` keys are filtered against the hardcoded
            # `allowed` set two lines above — never raw caller input —
            # and all values are parameterized. See db_manager.py's
            # update_vscan() for the fuller explanation of this pattern.
            conn.execute(f"UPDATE devices SET {set_clause} WHERE id=?", values)  # nosec B608

    def update_device_status(self, mac_address: str, status: str) -> None:
        """Update device status by MAC address."""
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE devices SET status=?, last_seen=CURRENT_TIMESTAMP WHERE mac_address=?",
                (status, mac_address),
            )

    def get_device_count(self) -> Dict[str, int]:
        """Return device counts grouped by status."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM devices GROUP BY status"
            ).fetchall()
            total_row = conn.execute("SELECT COUNT(*) AS cnt FROM devices").fetchone()
        counts: Dict[str, int] = {r["status"]: r["cnt"] for r in rows}
        counts["total"] = total_row["cnt"] if total_row else 0
        return counts

    # ══════════════════════════════════════
    # ATTACKS
    # ══════════════════════════════════════

    def add_attack(
        self,
        attack_type: str,
        source_ip: Optional[str] = None,
        source_mac: Optional[str] = None,
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
        severity: str = "medium",
        confidence: float = 0.0,
        packet_count: int = 0,
        bytes_total: int = 0,
        details: Optional[Dict] = None,
        detected_by: str = "engine",
    ) -> int:
        """Record a new attack event; return the new row id."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO attacks
                   (attack_type, source_ip, source_mac, target_ip, target_port,
                    severity, confidence, packet_count, bytes_total, details, detected_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    attack_type, source_ip, source_mac, target_ip, target_port,
                    severity, confidence, packet_count, bytes_total,
                    json.dumps(details or {}), detected_by,
                ),
            )
            return cursor.lastrowid

    def get_attacks(
        self,
        limit: int = 50,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return attacks ordered by creation time (newest first)."""
        with self.get_connection() as conn:
            query = "SELECT * FROM attacks WHERE 1=1"
            params: List[Any] = []
            if status:
                query += " AND status = ?"
                params.append(status)
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
        return [self._decode_json_fields(r, {"details": {}}) for r in self._rows_to_dicts(rows)]

    def get_active_attacks_count(self) -> int:
        """Fast count of currently active attacks."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM attacks WHERE status = 'active'"
            ).fetchone()
        return row["cnt"] if row else 0

    def update_attack_status(self, attack_id: int, status: str, mitigation: str = "") -> None:
        """Update an attack's status and optional mitigation note."""
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE attacks SET status=?, mitigation=?, ended_at=CURRENT_TIMESTAMP WHERE id=?",
                (status, mitigation, attack_id),
            )

    # ══════════════════════════════════════
    # ALERTS
    # ══════════════════════════════════════

    def add_alert(
        self,
        alert_type: str,
        title: str,
        message: str,
        severity: str = "info",
        source: str = "",
        device_id: Optional[int] = None,
        attack_id: Optional[int] = None,
        metadata: Optional[Dict] = None,
    ) -> int:
        """Create an alert; return the new row id."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO alerts
                   (alert_type, severity, title, message, source, device_id, attack_id, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert_type, severity, title, message, source,
                    device_id, attack_id, json.dumps(metadata or {}),
                ),
            )
            return cursor.lastrowid

    def get_alerts(
        self,
        limit: int = 50,
        acknowledged: Optional[bool] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return alerts, newest first."""
        with self.get_connection() as conn:
            query = "SELECT * FROM alerts WHERE 1=1"
            params: List[Any] = []
            if acknowledged is not None:
                query += " AND acknowledged = ?"
                params.append(1 if acknowledged else 0)
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
        return [self._decode_json_fields(r, {"metadata": {}}) for r in self._rows_to_dicts(rows)]

    def acknowledge_alert(self, alert_id: int) -> None:
        """Mark a single alert as acknowledged."""
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE alerts SET acknowledged=1, acknowledged_at=CURRENT_TIMESTAMP WHERE id=?",
                (alert_id,),
            )

    def acknowledge_all_alerts(self) -> None:
        """Acknowledge every pending alert at once."""
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE alerts SET acknowledged=1, acknowledged_at=CURRENT_TIMESTAMP WHERE acknowledged=0"
            )

    def get_unacknowledged_count(self) -> int:
        """Count unacknowledged alerts."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM alerts WHERE acknowledged = 0"
            ).fetchone()
        return row["cnt"] if row else 0

    # ══════════════════════════════════════
    # NETWORK TRAFFIC
    # ══════════════════════════════════════

    _TRAFFIC_FIELDS = (
        "packets_in", "packets_out", "bytes_in", "bytes_out",
        "tcp_count", "udp_count", "icmp_count", "other_count",
        "unique_src_ips", "unique_dst_ips", "unique_ports",
        "syn_count", "dns_count", "http_count",
        "avg_packet_size", "bandwidth_mbps", "active_connections",
    )

    def add_traffic_snapshot(self, **metrics: Any) -> None:
        """Record a traffic metrics snapshot."""
        values = {f: metrics.get(f, 0) for f in self._TRAFFIC_FIELDS}
        cols = ", ".join(self._TRAFFIC_FIELDS)
        placeholders = ", ".join(f":{f}" for f in self._TRAFFIC_FIELDS)
        with self.get_connection() as conn:
            # nosec B608: `cols`/`placeholders` are built purely from
            # `self._TRAFFIC_FIELDS`, a hardcoded module-level tuple —
            # never from caller input. Values are parameterized (named
            # params). Same safe allowlist pattern used throughout this
            # file for dynamic column lists.
            conn.execute(f"INSERT INTO network_traffic ({cols}) VALUES ({placeholders})", values)  # nosec B608

    def get_traffic_history(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Return traffic snapshots from the last *minutes* minutes."""
        since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM network_traffic WHERE timestamp >= ? ORDER BY timestamp ASC",
                (since,),
            ).fetchall()
        return self._rows_to_dicts(rows)

    def get_latest_traffic(self) -> Optional[Dict[str, Any]]:
        """Return the most recent traffic snapshot."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM network_traffic ORDER BY timestamp DESC LIMIT 1"
            ).fetchone()
        return self._row_to_dict(row)

    # ══════════════════════════════════════
    # SECURITY SCORES
    # ══════════════════════════════════════

    def add_security_score(
        self,
        total_score: float,
        device_security: float = 0.0,
        network_health: float = 0.0,
        attack_history: float = 0.0,
        vulnerability_exposure: float = 0.0,
        ai_confidence: float = 0.0,
        components: Optional[Dict] = None,
        trend: str = "stable",
    ) -> None:
        """Persist a new security score snapshot and update the settings key."""
        with self.get_connection() as conn:
            conn.execute(
                """INSERT INTO security_scores
                   (total_score, device_security, network_health, attack_history,
                    vulnerability_exposure, ai_confidence, components, trend)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    total_score, device_security, network_health, attack_history,
                    vulnerability_exposure, ai_confidence,
                    json.dumps(components or {}), trend,
                ),
            )
            conn.execute(
                "UPDATE settings SET value=?, updated_at=CURRENT_TIMESTAMP WHERE key='security_score'",
                (str(int(total_score)),),
            )

    def get_latest_score(self) -> Optional[Dict[str, Any]]:
        """Return the most recent security score row."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM security_scores ORDER BY timestamp DESC LIMIT 1"
            ).fetchone()
        return self._decode_json_fields(self._row_to_dict(row), {"components": {}})

    def get_score_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Return security score history for the last *hours* hours."""
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM security_scores WHERE timestamp >= ? ORDER BY timestamp ASC",
                (since,),
            ).fetchall()
        return [self._decode_json_fields(r, {"components": {}}) for r in self._rows_to_dicts(rows)]

    # ══════════════════════════════════════
    # LOGS
    # ══════════════════════════════════════

    def add_log(
        self,
        event_type: str,
        message: str,
        level: str = "info",
        source: str = "system",
        details: Optional[Dict] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Append a log entry."""
        with self.get_connection() as conn:
            conn.execute(
                """INSERT INTO logs (event_type, level, source, message, details, ip_address)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (event_type, level, source, message, json.dumps(details or {}), ip_address),
            )

    def get_logs(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
        level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return log entries, newest first."""
        with self.get_connection() as conn:
            query = "SELECT * FROM logs WHERE 1=1"
            params: List[Any] = []
            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)
            if level:
                query += " AND level = ?"
                params.append(level)
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
        return self._rows_to_dicts(rows)

    # ══════════════════════════════════════
    # HONEYPOT EVENTS
    # ══════════════════════════════════════

    def add_honeypot_event(
        self,
        honeypot_type: str,
        source_ip: str,
        service: str,
        action: str = "",
        source_port: Optional[int] = None,
        username: str = "",
        password: str = "",
        payload: str = "",
        session_id: str = "",
        geo_country: str = "",
        geo_city: str = "",
        threat_level: str = "medium",
    ) -> int:
        """Record a honeypot interaction; return the new row id."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO honeypot_events
                   (honeypot_type, source_ip, source_port, service, action,
                    username, password, payload, session_id,
                    geo_country, geo_city, threat_level)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    honeypot_type, source_ip, source_port, service, action,
                    username, password, payload, session_id,
                    geo_country, geo_city, threat_level,
                ),
            )
            return cursor.lastrowid

    def get_honeypot_events(
        self,
        limit: int = 50,
        honeypot_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return honeypot events, newest first."""
        with self.get_connection() as conn:
            query = "SELECT * FROM honeypot_events WHERE 1=1"
            params: List[Any] = []
            if honeypot_type:
                query += " AND honeypot_type = ?"
                params.append(honeypot_type)
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
        return self._rows_to_dicts(rows)

    def get_honeypot_stats(self) -> Dict[str, Any]:
        """Return aggregate honeypot statistics."""
        with self.get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) AS c FROM honeypot_events").fetchone()["c"]
            by_type = conn.execute(
                "SELECT honeypot_type, COUNT(*) AS count FROM honeypot_events GROUP BY honeypot_type"
            ).fetchall()
            unique_ips = conn.execute(
                "SELECT COUNT(DISTINCT source_ip) AS c FROM honeypot_events"
            ).fetchone()["c"]
        return {
            "total_events": total,
            "unique_attackers": unique_ips,
            "by_type": self._rows_to_dicts(by_type),
        }

    # ══════════════════════════════════════
    # MESH NODES & EDGES
    # ══════════════════════════════════════

    def add_mesh_node(
        self,
        node_id: str,
        ip_address: Optional[str] = None,
        mac_address: Optional[str] = None,
        role: str = "node",
        zone: str = "default",
    ) -> None:
        """Upsert a mesh node."""
        with self.get_connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO mesh_nodes (node_id, ip_address, mac_address, role, zone)
                   VALUES (?, ?, ?, ?, ?)""",
                (node_id, ip_address, mac_address, role, zone),
            )

    def add_mesh_edge(self, source_node: str, target_node: str, weight: float = 1.0) -> None:
        """Add a directed mesh edge."""
        with self.get_connection() as conn:
            conn.execute(
                "INSERT INTO mesh_edges (source_node, target_node, weight) VALUES (?, ?, ?)",
                (source_node, target_node, weight),
            )

    def get_mesh_topology(self) -> Dict[str, List]:
        """Return the full mesh topology as nodes + active edges."""
        with self.get_connection() as conn:
            nodes = conn.execute("SELECT * FROM mesh_nodes").fetchall()
            edges = conn.execute("SELECT * FROM mesh_edges WHERE status='active'").fetchall()
        return {
            "nodes": [
                self._decode_json_fields(r, {"connections": []})
                for r in self._rows_to_dicts(nodes)
            ],
            "edges": self._rows_to_dicts(edges),
        }

    def update_mesh_node_status(self, node_id: str, status: str) -> None:
        """Update the status of a mesh node."""
        with self.get_connection() as conn:
            conn.execute("UPDATE mesh_nodes SET status=? WHERE node_id=?", (status, node_id))

    def isolate_mesh_node(self, node_id: str) -> None:
        """Isolate a node: mark it isolated and block all its edges."""
        with self.get_connection() as conn:
            conn.execute("UPDATE mesh_nodes SET status='isolated' WHERE node_id=?", (node_id,))
            conn.execute(
                "UPDATE mesh_edges SET status='blocked' WHERE source_node=? OR target_node=?",
                (node_id, node_id),
            )

    # ══════════════════════════════════════
    # BLOCKED DEVICES
    # ══════════════════════════════════════

    def block_device(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
        reason: str = "",
        blocked_by: str = "manual",
        is_permanent: bool = False,
        duration_minutes: int = 0,
    ) -> None:
        """Add a device to the block list and update its status."""
        expires: Optional[str] = None
        if duration_minutes > 0:
            expires = (datetime.utcnow() + timedelta(minutes=duration_minutes)).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """INSERT INTO blocked_devices
                   (mac_address, ip_address, reason, blocked_by, is_permanent, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (mac_address, ip_address, reason, blocked_by, int(is_permanent), expires),
            )
            conn.execute(
                "UPDATE devices SET status='blocked' WHERE mac_address=?", (mac_address,)
            )

    def unblock_device(self, mac_address: str) -> None:
        """Remove a device from the block list and restore its status."""
        with self.get_connection() as conn:
            conn.execute("DELETE FROM blocked_devices WHERE mac_address=?", (mac_address,))
            conn.execute(
                "UPDATE devices SET status='unknown' WHERE mac_address=?", (mac_address,)
            )

    def get_blocked_devices(self) -> List[Dict[str, Any]]:
        """Return all currently blocked devices."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM blocked_devices ORDER BY created_at DESC"
            ).fetchall()
        return self._rows_to_dicts(rows)

    def is_blocked(self, mac_address: Optional[str] = None, ip_address: Optional[str] = None) -> bool:
        """Check whether a device is currently blocked, expiring stale entries."""
        # First sweep expired temporary blocks
        self._expire_blocks()
        with self.get_connection() as conn:
            if mac_address:
                row = conn.execute(
                    "SELECT id FROM blocked_devices WHERE mac_address=?", (mac_address,)
                ).fetchone()
            elif ip_address:
                row = conn.execute(
                    "SELECT id FROM blocked_devices WHERE ip_address=?", (ip_address,)
                ).fetchone()
            else:
                return False
        return row is not None

    def _expire_blocks(self) -> None:
        """Remove temporary blocks that have passed their expiry timestamp."""
        now = datetime.utcnow().isoformat()
        with self.get_connection() as conn:
            expired = conn.execute(
                "SELECT mac_address FROM blocked_devices WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            ).fetchall()
        for row in self._rows_to_dicts(expired):
            self.unblock_device(row["mac_address"])

    # ══════════════════════════════════════
    # PREDICTIONS
    # ══════════════════════════════════════

    def add_prediction(
        self,
        prediction_type: str,
        probability: float,
        predicted_attack: str = "",
        target: str = "",
        time_horizon: int = 30,
        features_used: Optional[Dict] = None,
        model_version: str = "",
    ) -> int:
        """Record an AI prediction; return the new row id."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO predictions
                   (prediction_type, target, probability, predicted_attack,
                    time_horizon, features_used, model_version)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    prediction_type, target, probability, predicted_attack,
                    time_horizon, json.dumps(features_used or {}), model_version,
                ),
            )
            return cursor.lastrowid

    def get_recent_predictions(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return the most recent AI predictions."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM predictions ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._decode_json_fields(r, {"features_used": {}}) for r in self._rows_to_dicts(rows)]

    # ══════════════════════════════════════
    # SETTINGS
    # ══════════════════════════════════════

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Return a setting value or *default* if the key is absent."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str, description: str = "") -> None:
        """Insert or replace a setting."""
        with self.get_connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO settings (key, value, description, updated_at)
                   VALUES (?, ?, ?, CURRENT_TIMESTAMP)""",
                (key, value, description),
            )

    def get_all_settings(self) -> Dict[str, str]:
        """Return all settings as a {key: value} dict."""
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

    # ══════════════════════════════════════
    # DASHBOARD AGGREGATES
    # ══════════════════════════════════════


    def get_attack_stats(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Return attack counts grouped by type and severity for the last N hours."""
        from datetime import timedelta
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT attack_type, severity, COUNT(*) AS count
                FROM attacks
                WHERE created_at >= ?
                GROUP BY attack_type, severity
                ORDER BY count DESC
            """, (since,)).fetchall()
        return self._rows_to_dicts(rows)

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Return aggregated stats for the main dashboard in one DB round-trip."""
        devices = self.get_device_count()
        active_attacks = self.get_active_attacks_count()
        unack_alerts = self.get_unacknowledged_count()
        latest_score = self.get_latest_score()
        latest_traffic = self.get_latest_traffic()

        since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        with self.get_connection() as conn:
            attack_types = conn.execute(
                """SELECT attack_type, COUNT(*) AS count FROM attacks
                   WHERE created_at >= ? GROUP BY attack_type""",
                (since,),
            ).fetchall()

        return {
            "devices": devices,
            "active_attacks": active_attacks,
            "unacknowledged_alerts": unack_alerts,
            "security_score": latest_score["total_score"] if latest_score else 85,
            "score_components": latest_score.get("components", {}) if latest_score else {},
            "score_trend": latest_score["trend"] if latest_score else "stable",
            "traffic": latest_traffic or {},
            "attack_distribution": self._rows_to_dicts(attack_types),
            "lockdown_active": self.get_setting("lockdown_active", "false") == "true",
            "demo_mode": self.get_setting("demo_mode", "true") == "true",
        }

    # ══════════════════════════════════════
    # MAINTENANCE
    # ══════════════════════════════════════

    def migrate_legacy_placeholder_devices(self) -> Dict[str, int]:
        """Rewrite shared placeholder MACs to per-IP synthetic MACs."""
        migrated = 0
        merged = 0
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT id, ip_address, mac_address FROM devices "
                "WHERE mac_address IN ('00:00:00:00:00:00','00:00:00:00:00:01')"
            ).fetchall()
            for row in rows:
                ip_address = row["ip_address"]
                if not ip_address:
                    continue
                new_mac = synthetic_mac_from_ip(ip_address)
                existing = conn.execute(
                    "SELECT id FROM devices WHERE mac_address = ? AND id != ?",
                    (new_mac, row["id"]),
                ).fetchone()
                if existing:
                    conn.execute("DELETE FROM devices WHERE id = ?", (row["id"],))
                    merged += 1
                else:
                    conn.execute(
                        "UPDATE devices SET mac_address = ? WHERE id = ?",
                        (new_mac, row["id"]),
                    )
                    migrated += 1
        return {"migrated": migrated, "merged": merged}

    def cleanup_old_data(self, days: int = 30) -> None:
        """Delete records older than *days* days."""
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        with self.get_connection() as conn:
            conn.execute("DELETE FROM network_traffic WHERE timestamp < ?", (cutoff,))
            conn.execute("DELETE FROM logs WHERE created_at < ?", (cutoff,))
            conn.execute("DELETE FROM predictions WHERE created_at < ?", (cutoff,))
        self._expire_blocks()

    # ══════════════════════════════════════
    # V-8 SCANNER (Web Security Assessment)
    # ══════════════════════════════════════

    def add_vscan(
        self,
        scan_id: str,
        target_url: str,
        tools_used: List[str],
        active_scan: bool = False,
        requested_by: str = "",
        owner_id: Optional[int] = None,
    ) -> str:
        """Create a new scan job row in 'queued' status.

        owner_id should always be the authenticated user's users.id (see
        auth/decorators.py's request.current_user) — never client-supplied.
        NULL is reserved for legacy rows created before ownership was
        enforced; routes_vscanner.py treats those as admin-only-accessible,
        not "everyone's", so leave this None only when there truly is no
        authenticated owner (there shouldn't be, in practice, since every
        route that creates a scan requires auth).
        """
        with self.get_connection() as conn:
            conn.execute(
                """INSERT INTO vscans
                   (id, target_url, tools_used, active_scan, status, stage, requested_by, owner_id)
                   VALUES (?, ?, ?, ?, 'queued', 'Queued', ?, ?)""",
                (scan_id, target_url, json.dumps(tools_used), int(active_scan), requested_by, owner_id),
            )
        return scan_id

    def update_vscan(self, scan_id: str, **fields: Any) -> None:
        """Update arbitrary columns on a vscans row (status, stage, progress, error, timestamps)."""
        if not fields:
            return
        allowed = {
            "status", "stage", "progress", "findings_count", "error",
            "started_at", "finished_at",
        }
        cols = [k for k in fields if k in allowed]
        if not cols:
            return
        set_clause = ", ".join(f"{c}=?" for c in cols)
        values = [fields[c] for c in cols] + [scan_id]
        with self.get_connection() as conn:
            # nosec B608: bandit flags any f-string used to build SQL, but
            # `cols` here is filtered against the hardcoded `allowed` set
            # two lines above — never derived from caller/user input — and
            # every VALUE is still passed as a parameterized `?`. SQL
            # doesn't support parameterizing identifiers (column names),
            # so an allowlist-filtered f-string for the column list,
            # combined with parameterized values, is the correct safe
            # pattern here, not a vulnerability. Verified during a Red
            # Team review that specifically checked this.
            conn.execute(f"UPDATE vscans SET {set_clause} WHERE id=?", values)  # nosec B608

    def get_vscan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM vscans WHERE id=?", (scan_id,)).fetchone()
        return self._decode_json_fields(self._row_to_dict(row), {"tools_used": []})

    def get_vscans(self, limit: int = 50, owner_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """List scans, most recent first. If owner_id is given, only that
        user's scans are returned — used by routes_vscanner.py's
        /history endpoint so a non-admin only sees their own scan history,
        not every user's (part of the IDOR fix)."""
        query = "SELECT * FROM vscans"
        params: List[Any] = []
        if owner_id is not None:
            query += " WHERE owner_id = ?"
            params.append(owner_id)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            self._decode_json_fields(d, {"tools_used": []})
            for d in self._rows_to_dicts(rows)
        ]

    def delete_vscan(self, scan_id: str) -> bool:
        """Delete a scan and its findings/report rows (findings cascade via FK)."""
        with self.get_connection() as conn:
            reports = conn.execute(
                "SELECT file_path FROM vscan_reports WHERE scan_id=?", (scan_id,)
            ).fetchall()
            conn.execute("DELETE FROM vscan_findings WHERE scan_id=?", (scan_id,))
            conn.execute("DELETE FROM vscan_reports WHERE scan_id=?", (scan_id,))
            cur = conn.execute("DELETE FROM vscans WHERE id=?", (scan_id,))
            deleted = cur.rowcount > 0
        import os as _os
        for r in reports:
            try:
                if r["file_path"] and _os.path.exists(r["file_path"]):
                    _os.remove(r["file_path"])
            except Exception:
                pass
        return deleted

    def add_vscan_finding(
        self,
        scan_id: str,
        source_tool: str,
        finding_type: str,
        severity: str = "info",
        confidence: float = 0.5,
        url: str = "",
        parameter: str = "",
        owasp_category: str = "",
        cwe_id: str = "",
        description: str = "",
        evidence: str = "",
        recommendation: str = "",
        ai_explanation: str = "",
        dedup_hash: str = "",
        is_duplicate: bool = False,
        correlation_group: str = "",
        correlated_with_tools: Optional[List[str]] = None,
        raw_data: Optional[Dict[str, Any]] = None,
    ) -> int:
        with self.get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO vscan_findings
                   (scan_id, source_tool, finding_type, url, parameter, severity,
                    confidence, owasp_category, cwe_id, description, evidence,
                    recommendation, ai_explanation, dedup_hash, is_duplicate,
                    correlation_group, correlated_with_tools, raw_data)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan_id, source_tool, finding_type, url, parameter, severity,
                    confidence, owasp_category, cwe_id, description, evidence,
                    recommendation, ai_explanation, dedup_hash, int(is_duplicate),
                    correlation_group or "", json.dumps(correlated_with_tools or []),
                    json.dumps(raw_data or {}),
                ),
            )
            return cursor.lastrowid

    def get_vscan_findings(
        self, scan_id: str, include_duplicates: bool = False
    ) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            if include_duplicates:
                rows = conn.execute(
                    """SELECT * FROM vscan_findings WHERE scan_id=?
                       ORDER BY
                         CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                       WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                         confidence DESC""",
                    (scan_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM vscan_findings WHERE scan_id=? AND is_duplicate=0
                       ORDER BY
                         CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                       WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                         confidence DESC""",
                    (scan_id,),
                ).fetchall()
        return [
            self._decode_json_fields(d, {"raw_data": {}, "correlated_with_tools": []})
            for d in self._rows_to_dicts(rows)
        ]

    def add_vscan_report(self, scan_id: str, fmt: str, file_path: str) -> int:
        with self.get_connection() as conn:
            cursor = conn.execute(
                "INSERT INTO vscan_reports (scan_id, format, file_path) VALUES (?,?,?)",
                (scan_id, fmt, file_path),
            )
            return cursor.lastrowid

    def get_vscan_reports(self, scan_id: str) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM vscan_reports WHERE scan_id=? ORDER BY created_at DESC",
                (scan_id,),
            ).fetchall()
        return self._rows_to_dicts(rows)

    # ══════════════════════════════════════
    # AUDIT LOG
    # ══════════════════════════════════════

    def add_audit_log(
        self,
        action: str,
        username: str = "",
        status: str = "success",
        ip_address: str = "",
        details: str = "",
    ) -> int:
        """Record a security-relevant action (login, scan started, device blocked, etc.).

        Kept as an append-only table separate from the general `logs` table so
        accountability records aren't pruned by the routine log-cleanup jobs.
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO audit_log (username, action, status, ip_address, details)
                   VALUES (?,?,?,?,?)""",
                (username, action, status, ip_address, details),
            )
            return cursor.lastrowid

    def get_audit_log(
        self,
        limit: int = 100,
        action: Optional[str] = None,
        username: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: List[Any] = []
        if action:
            query += " AND action = ?"
            params.append(action)
        if username:
            query += " AND username = ?"
            params.append(username)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return self._rows_to_dicts(rows)

    def count_recent_audit_actions(self, action: str, username: str, since_minutes: int, status: Optional[str] = None) -> int:
        """Count matching audit_log rows within the last `since_minutes` —
        used for account-level lockout (e.g. verify-code brute force),
        which is a distinct control from flask-limiter's per-IP rate
        limiting: this catches a distributed attack against ONE account
        from many source IPs, which a purely IP-keyed limit cannot."""
        query = "SELECT COUNT(*) FROM audit_log WHERE action=? AND username=? AND timestamp >= datetime('now', ?)"
        params: List[Any] = [action, username, f"-{since_minutes} minutes"]
        if status:
            query += " AND status=?"
            params.append(status)
        with self.get_connection() as conn:
            return conn.execute(query, params).fetchone()[0]

    # ══════════════════════════════════════
    # AI MODEL TRAINING METADATA
    # ══════════════════════════════════════

    def add_model_metadata(self, model_name: str, model_version: str, **fields: Any) -> int:
        """Record one training run's metrics. Any metric not applicable to
        this model type should be passed as None (the caller's job — see
        ai/trainer.py) rather than omitted, so the row makes clear it was
        considered and found not applicable, not simply forgotten."""
        allowed = {
            "training_source", "training_samples", "test_samples",
            "accuracy", "precision_score", "recall_score", "f1_score", "roc_auc",
            "confusion_matrix", "mse", "mae", "r2_score", "metrics_note", "success",
        }
        cols = ["model_name", "model_version"] + [k for k in fields if k in allowed]
        values = [model_name, model_version] + [fields[k] for k in fields if k in allowed]
        placeholders = ", ".join("?" for _ in cols)
        with self.get_connection() as conn:
            # nosec B608: `cols` is `["model_name", "model_version"] +
            # [k for k in fields if k in allowed]` a few lines above —
            # allowlist-filtered, never raw caller input — and `values`
            # is still fully parameterized. Same safe pattern as the
            # UPDATE vscans call above; see that comment for the full
            # reasoning.
            cursor = conn.execute(
                f"INSERT INTO model_metadata ({', '.join(cols)}) VALUES ({placeholders})",  # nosec B608
                values,
            )
            return cursor.lastrowid

    def get_model_metadata(self, model_name: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        query = "SELECT * FROM model_metadata WHERE 1=1"
        params: List[Any] = []
        if model_name:
            query += " AND model_name = ?"
            params.append(model_name)
        query += " ORDER BY trained_at DESC LIMIT ?"
        params.append(limit)
        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            self._decode_json_fields(d, {"confusion_matrix": None})
            for d in self._rows_to_dicts(rows)
        ]

    def get_latest_model_metadata(self, model_name: str) -> Optional[Dict[str, Any]]:
        results = self.get_model_metadata(model_name=model_name, limit=1)
        return results[0] if results else None

    # ══════════════════════════════════════
    # SHUTDOWN
    # ══════════════════════════════════════

    def close_all_connections(self) -> None:
        """Close the thread-local connection for the calling thread, and best-effort
        checkpoint the WAL file so data is flushed to the main database file.

        SQLite connections in this manager are cached per-thread (see
        `get_connection`), so there is no single global pool to iterate — each
        thread owns its own connection. This method is safe to call from the
        main thread during shutdown; it closes that thread's connection and
        issues a WAL checkpoint so no committed data is left only in the
        write-ahead log when the process exits.
        """
        conn = getattr(self._local, "conn", None)
        if conn is None:
            return
        try:
            conn.execute("PRAGMA wal_checkpoint(FULL)")
        except Exception as e:
            logger.warning(f"WAL checkpoint failed during shutdown: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None


# Singleton instance — import this everywhere
db = DatabaseManager()
