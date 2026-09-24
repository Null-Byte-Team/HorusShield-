"""
HorusShield Database Models & Schema
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SQLite database schema for all HorusShield data.
"""

import sqlite3
import os

# Path to database — frozen-safe (works in PyInstaller EXE).
# HORUS_DB_PATH, if set, overrides the directory entirely (used by the Docker
# image to point at a mounted volume); default behavior is unchanged.
import sys as _sys
_env_db_path = os.environ.get("HORUS_DB_PATH", "").strip()
if _env_db_path:
    DB_PATH = os.path.abspath(_env_db_path)
    DB_DIR = os.path.dirname(DB_PATH)
elif getattr(_sys, 'frozen', False):
    DB_DIR = os.path.join(os.path.dirname(_sys.executable), 'database')
    DB_PATH = os.path.join(DB_DIR, 'horus.db')
else:
    DB_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_PATH = os.path.join(DB_DIR, 'horus.db')
if DB_DIR:
    os.makedirs(DB_DIR, exist_ok=True)

SCHEMA_SQL = """
-- ═══════════════════════════════════════════════
-- HorusShield Database Schema
-- ═══════════════════════════════════════════════

-- ── Devices ──
CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address     TEXT UNIQUE NOT NULL,
    ip_address      TEXT,
    hostname        TEXT DEFAULT 'Unknown',
    vendor          TEXT DEFAULT 'Unknown',
    manufacturer    TEXT DEFAULT 'Unknown',
    device_type     TEXT DEFAULT 'Unknown Device',
    model           TEXT DEFAULT '',
    os_info         TEXT DEFAULT '',
    confidence      INTEGER DEFAULT 0,
    evidence        TEXT DEFAULT '[]',       -- JSON array of evidence strings
    fingerprint     TEXT DEFAULT '{}',       -- JSON object of raw signals
    open_ports      TEXT DEFAULT '[]',       -- JSON array
    status          TEXT DEFAULT 'unknown',  -- trusted, unknown, blocked, suspicious
    is_gateway      INTEGER DEFAULT 0,
    risk_score      REAL DEFAULT 0.0,        -- 0-100
    first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity   TEXT DEFAULT '',
    notes           TEXT DEFAULT '',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- ── Attacks ──
CREATE TABLE IF NOT EXISTS attacks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type     TEXT NOT NULL,            -- ddos, port_scan, brute_force, anomaly, malware, data_exfiltration
    source_ip       TEXT,
    source_mac      TEXT,
    target_ip       TEXT,
    target_port     INTEGER,
    severity        TEXT DEFAULT 'medium',    -- critical, high, medium, low, info
    confidence      REAL DEFAULT 0.0,         -- 0-1 AI confidence
    packet_count    INTEGER DEFAULT 0,
    bytes_total     INTEGER DEFAULT 0,
    details         TEXT DEFAULT '{}',        -- JSON details
    status          TEXT DEFAULT 'active',    -- active, mitigated, false_positive, investigating
    mitigation      TEXT DEFAULT '',
    detected_by     TEXT DEFAULT 'engine',    -- engine, ai, honeypot, manual
    started_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ended_at        TIMESTAMP,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Alerts ──
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type      TEXT NOT NULL,            -- new_device, unknown_device, attack, anomaly, prediction, system, lockdown
    severity        TEXT DEFAULT 'info',      -- critical, high, medium, low, info
    title           TEXT NOT NULL,
    message         TEXT NOT NULL,
    source          TEXT DEFAULT '',
    device_id       INTEGER,
    attack_id       INTEGER,
    acknowledged    INTEGER DEFAULT 0,
    auto_resolved   INTEGER DEFAULT 0,
    metadata        TEXT DEFAULT '{}',        -- JSON additional data
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id),
    FOREIGN KEY (attack_id) REFERENCES attacks(id)
);

-- ── Network Traffic Metrics ──
CREATE TABLE IF NOT EXISTS network_traffic (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    packets_in      INTEGER DEFAULT 0,
    packets_out     INTEGER DEFAULT 0,
    bytes_in        INTEGER DEFAULT 0,
    bytes_out       INTEGER DEFAULT 0,
    tcp_count       INTEGER DEFAULT 0,
    udp_count       INTEGER DEFAULT 0,
    icmp_count      INTEGER DEFAULT 0,
    other_count     INTEGER DEFAULT 0,
    unique_src_ips  INTEGER DEFAULT 0,
    unique_dst_ips  INTEGER DEFAULT 0,
    unique_ports    INTEGER DEFAULT 0,
    syn_count       INTEGER DEFAULT 0,
    dns_count       INTEGER DEFAULT 0,
    http_count      INTEGER DEFAULT 0,
    avg_packet_size REAL DEFAULT 0.0,
    bandwidth_mbps  REAL DEFAULT 0.0,
    active_connections INTEGER DEFAULT 0,
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Security Scores ──
CREATE TABLE IF NOT EXISTS security_scores (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    total_score     REAL DEFAULT 0.0,         -- 0-100
    device_security REAL DEFAULT 0.0,
    network_health  REAL DEFAULT 0.0,
    attack_history  REAL DEFAULT 0.0,
    vulnerability_exposure REAL DEFAULT 0.0,
    ai_confidence   REAL DEFAULT 0.0,
    components      TEXT DEFAULT '{}',        -- JSON breakdown
    trend           TEXT DEFAULT 'stable',    -- improving, stable, declining
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── System Logs ──
CREATE TABLE IF NOT EXISTS logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type      TEXT NOT NULL,            -- system, engine, ai, attack, device, honeypot, mesh, user
    level           TEXT DEFAULT 'info',      -- debug, info, warning, error, critical
    source          TEXT DEFAULT 'system',
    message         TEXT NOT NULL,
    details         TEXT DEFAULT '{}',        -- JSON
    ip_address      TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Honeypot Events ──
CREATE TABLE IF NOT EXISTS honeypot_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    honeypot_type   TEXT NOT NULL,            -- ssh, http, ftp, telnet
    source_ip       TEXT NOT NULL,
    source_port     INTEGER,
    service         TEXT NOT NULL,
    action          TEXT DEFAULT '',           -- login_attempt, command, download, scan
    username        TEXT DEFAULT '',
    password        TEXT DEFAULT '',
    payload         TEXT DEFAULT '',
    session_id      TEXT DEFAULT '',
    geo_country     TEXT DEFAULT '',
    geo_city        TEXT DEFAULT '',
    threat_level    TEXT DEFAULT 'medium',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Mesh Network Nodes ──
CREATE TABLE IF NOT EXISTS mesh_nodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id         TEXT UNIQUE NOT NULL,
    ip_address      TEXT,
    mac_address     TEXT,
    role            TEXT DEFAULT 'node',      -- gateway, node, sensor, honeypot
    status          TEXT DEFAULT 'active',    -- active, isolated, compromised, offline
    zone            TEXT DEFAULT 'default',
    connections     TEXT DEFAULT '[]',        -- JSON array of connected node_ids
    centrality      REAL DEFAULT 0.0,         -- betweenness centrality
    risk_score      REAL DEFAULT 0.0,
    last_heartbeat  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Mesh Edges ──
CREATE TABLE IF NOT EXISTS mesh_edges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_node     TEXT NOT NULL,
    target_node     TEXT NOT NULL,
    weight          REAL DEFAULT 1.0,
    traffic_volume  INTEGER DEFAULT 0,
    latency_ms      REAL DEFAULT 0.0,
    status          TEXT DEFAULT 'active',    -- active, blocked, degraded
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_node) REFERENCES mesh_nodes(node_id),
    FOREIGN KEY (target_node) REFERENCES mesh_nodes(node_id)
);

-- ── Settings (Key-Value Store) ──
CREATE TABLE IF NOT EXISTS settings (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    description     TEXT DEFAULT '',
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Blocked Devices ──
CREATE TABLE IF NOT EXISTS blocked_devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address     TEXT NOT NULL,
    ip_address      TEXT,
    reason          TEXT DEFAULT '',
    blocked_by      TEXT DEFAULT 'manual',    -- manual, auto, lockdown, ai
    is_permanent    INTEGER DEFAULT 0,
    expires_at      TIMESTAMP,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── AI Predictions ──
CREATE TABLE IF NOT EXISTS predictions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    prediction_type TEXT NOT NULL,            -- attack_likelihood, anomaly_score, threat_level
    target          TEXT DEFAULT '',
    probability     REAL DEFAULT 0.0,
    predicted_attack TEXT DEFAULT '',
    time_horizon    INTEGER DEFAULT 30,       -- seconds ahead
    features_used   TEXT DEFAULT '{}',        -- JSON
    model_version   TEXT DEFAULT '',
    was_correct     INTEGER DEFAULT -1,       -- -1=unknown, 0=incorrect, 1=correct
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── V-8 Scanner: Web Security Assessment ──
CREATE TABLE IF NOT EXISTS vscans (
    id              TEXT PRIMARY KEY,          -- generated session id
    target_url      TEXT NOT NULL,
    tools_used      TEXT DEFAULT '[]',          -- JSON list, e.g. ["nmap","zap","nikto"]
    active_scan     INTEGER DEFAULT 0,          -- 1 if ZAP active scan was opted into
    status          TEXT DEFAULT 'queued',      -- queued, running, completed, failed, stopped
    stage           TEXT DEFAULT '',            -- human-readable current stage
    progress        INTEGER DEFAULT 0,          -- 0-100
    findings_count  INTEGER DEFAULT 0,
    error           TEXT DEFAULT '',
    requested_by    TEXT DEFAULT '',            -- display-only email, server-derived from the
                                                 -- authenticated session (see routes_vscanner.py) —
                                                 -- NOT used for authorization; owner_id is.
    owner_id        INTEGER,                    -- users.id of the creator. NULL = legacy row created
                                                 -- before ownership was enforced (treated as
                                                 -- admin-only-accessible, not "everyone's" — see
                                                 -- routes_vscanner.py's _is_owner_or_admin). Fixes a
                                                 -- confirmed IDOR: any authenticated user could
                                                 -- previously read/delete any other user's scan.
    started_at      TIMESTAMP,
    finished_at     TIMESTAMP,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vscan_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES vscans(id) ON DELETE CASCADE,
    source_tool     TEXT NOT NULL,              -- zap, nikto, nmap
    finding_type    TEXT NOT NULL,               -- e.g. "SQL Injection", "Open Port"
    url             TEXT DEFAULT '',
    parameter       TEXT DEFAULT '',
    severity        TEXT DEFAULT 'info',         -- critical, high, medium, low, info
    confidence      REAL DEFAULT 0.5,            -- 0.0-1.0, AI Cortex assigned
    owasp_category  TEXT DEFAULT '',
    cwe_id          TEXT DEFAULT '',
    description     TEXT DEFAULT '',
    evidence        TEXT DEFAULT '',
    recommendation  TEXT DEFAULT '',
    ai_explanation  TEXT DEFAULT '',
    dedup_hash      TEXT DEFAULT '',
    is_duplicate    INTEGER DEFAULT 0,
    correlation_group    TEXT DEFAULT '',        -- shared-asset key linking related findings (see ai/vscanner_cortex.py correlate())
    correlated_with_tools TEXT DEFAULT '[]',      -- JSON list of other source_tools that also flagged this same asset
    raw_data        TEXT DEFAULT '{}',           -- JSON, original tool output
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vscan_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES vscans(id) ON DELETE CASCADE,
    format          TEXT NOT NULL,               -- pdf, html, json
    file_path       TEXT NOT NULL,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Audit Log — records security-relevant actions for accountability ──
-- ── AI Model Training Metadata ──
-- One row per training run per model. Metrics that don't apply to a given
-- model type (e.g. classification precision/recall for a regressor, or any
-- supervised metric for unsupervised anomaly detection without ground
-- truth) are stored as NULL, with `metrics_note` explaining why — never a
-- fabricated number standing in for "not applicable."
CREATE TABLE IF NOT EXISTS model_metadata (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name      TEXT NOT NULL,           -- threat_classifier, attack_predictor, anomaly_detector
    model_version   TEXT NOT NULL,           -- timestamp-based, e.g. 20260101T120000
    trained_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    training_source TEXT DEFAULT '',         -- 'history' or 'synthetic'
    training_samples INTEGER DEFAULT 0,
    test_samples    INTEGER DEFAULT 0,
    accuracy        REAL,
    precision_score REAL,
    recall_score    REAL,
    f1_score        REAL,
    roc_auc         REAL,
    confusion_matrix TEXT DEFAULT '',        -- JSON, only for classifiers
    mse             REAL,                    -- regression metrics (attack_predictor)
    mae             REAL,
    r2_score        REAL,
    metrics_note    TEXT DEFAULT '',         -- honest explanation when a metric above is NULL
    success         INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    username        TEXT DEFAULT '',
    action          TEXT NOT NULL,           -- e.g. login, logout, scan_started, device_blocked
    status          TEXT DEFAULT 'success',  -- success, failure
    ip_address      TEXT DEFAULT '',
    details         TEXT DEFAULT ''
);

-- ── Indexes for Performance ──
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_attacks_type ON attacks(attack_type);
CREATE INDEX IF NOT EXISTS idx_attacks_severity ON attacks(severity);
CREATE INDEX IF NOT EXISTS idx_attacks_status ON attacks(status);
CREATE INDEX IF NOT EXISTS idx_attacks_created ON attacks(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON network_traffic(timestamp);
CREATE INDEX IF NOT EXISTS idx_scores_timestamp ON security_scores(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_type ON logs(event_type);
CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at);
CREATE INDEX IF NOT EXISTS idx_honeypot_ip ON honeypot_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_honeypot_created ON honeypot_events(created_at);
CREATE INDEX IF NOT EXISTS idx_blocked_mac ON blocked_devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_predictions_created ON predictions(created_at);
CREATE INDEX IF NOT EXISTS idx_vscans_status ON vscans(status);
CREATE INDEX IF NOT EXISTS idx_vscans_owner ON vscans(owner_id);
CREATE INDEX IF NOT EXISTS idx_vscans_created ON vscans(created_at);
CREATE INDEX IF NOT EXISTS idx_vscan_findings_scan ON vscan_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_vscan_findings_severity ON vscan_findings(severity);
CREATE INDEX IF NOT EXISTS idx_vscan_reports_scan ON vscan_reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_model_metadata_name ON model_metadata(model_name);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);


-- ── Users & Auth ──
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT,
    full_name       TEXT DEFAULT '',
    avatar_url      TEXT DEFAULT '',
    provider        TEXT DEFAULT 'local',    -- local, google
    google_id       TEXT,
    is_verified     INTEGER DEFAULT 0,
    is_active       INTEGER DEFAULT 1,
    role            TEXT DEFAULT 'analyst',   -- 'analyst' by default (changed from 'admin' — a
                                               -- confirmed Red Team finding: every new signup got
                                               -- full admin/terminal access with zero gating). The
                                               -- FIRST account ever registered still becomes admin
                                               -- automatically (see auth/auth_manager.py's
                                               -- _next_role()) so a fresh install always has one
                                               -- admin able to promote others — every account after
                                               -- that defaults to analyst.
    verification_code TEXT DEFAULT '',
    code_expires_at TIMESTAMP,
    last_login      TIMESTAMP,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS auth_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    token           TEXT UNIQUE NOT NULL,
    expires_at      TIMESTAMP NOT NULL,
    ip_address      TEXT DEFAULT '',
    user_agent      TEXT DEFAULT '',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON auth_sessions(token);

-- ── Default Settings ──
INSERT OR IGNORE INTO settings (key, value, description) VALUES
    ('demo_mode', 'false', 'Enable demo/training mode'),
    ('language', 'en', 'Interface language (en/ar)'),
    ('theme', 'dark', 'UI theme (dark/light/emergency)'),
    ('lockdown_active', 'false', 'Emergency lockdown mode'),
    ('honeypot_enabled', 'false', 'Honeypot system active'),
    ('auto_block', 'true', 'Automatically block suspicious devices'),
    ('ai_enabled', 'true', 'AI detection engine active'),
    ('monitor_active', 'true', 'Network monitoring active'),
    ('scan_interval', '30', 'Device scan interval in seconds'),
    ('alert_sound', 'true', 'Play sound on critical alerts'),
    ('report_auto_generate', 'false', 'Auto-generate daily reports'),
    ('mesh_defense', 'true', 'Mesh defense system active'),
    ('security_score', '85', 'Current security score'),
    ('smtp_host', '', 'SMTP server host (e.g. smtp.gmail.com)'),
    ('smtp_port', '587', 'SMTP server port'),
    ('smtp_user', '', 'SMTP login email address'),
    ('smtp_pass', '', 'SMTP login password or App Password'),
    ('smtp_from_name', 'HorusShield Security', 'Sender display name'),
    ('google_client_id', '84532770868-ere6dbvhfi09s719g7r50rj1v49a0g1e.apps.googleusercontent.com', 'Google OAuth 2.0 Client ID for Sign-In with Google');
"""


def _migrate_devices_table(conn):
    """Safely add new fingerprinting columns to existing devices table if absent."""
    try:
        cursor = conn.execute("PRAGMA table_info(devices)")
        cols = {row[1] for row in cursor.fetchall()}
        new_cols = [
            ("manufacturer", "TEXT DEFAULT 'Unknown'"),
            ("model", "TEXT DEFAULT ''"),
            ("confidence", "INTEGER DEFAULT 0"),
            ("evidence", "TEXT DEFAULT '[]'"),
            ("fingerprint", "TEXT DEFAULT '{}'"),
        ]
        for col_name, col_def in new_cols:
            if col_name not in cols:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_def}")
        conn.commit()
    except Exception:
        pass


def init_database(db_path=None):
    """Initialize the database with schema and apply non-destructive migrations."""
    path = db_path or DB_PATH
    dirname = os.path.dirname(path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA_SQL)
    _migrate_devices_table(conn)
    conn.commit()
    conn.close()
    return path



if __name__ == "__main__":
    init_database()
    print(f"[✓] HorusShield database initialized at {DB_PATH}")
