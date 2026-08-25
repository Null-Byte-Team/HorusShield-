#!/usr/bin/env python3
"""
CI helper: verify the database schema initializes cleanly from scratch,
every expected table exists, and basic read/write actually works.

Run with HORUS_DB_PATH pointing at a throw-away path — never the real
backend/database/horus.db.
"""

import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
sys.path.insert(0, BACKEND_DIR)

os.environ.setdefault("HORUS_ENV", "development")
os.environ.setdefault("HORUS_SECRET_KEY", "ci-db-check-secret")

EXPECTED_TABLES = {
    "devices",
    "alerts",
    "blocked_devices",
    "network_traffic",
    "logs",
    "settings",
    "predictions",
    "vscans",
    "vscan_findings",
    "vscan_reports",
    "audit_log",
}


def main():
    db_path = os.environ.get("HORUS_DB_PATH")
    if not db_path:
        print("❌ Set HORUS_DB_PATH to a throw-away path before running this script")
        sys.exit(1)
    if os.path.exists(db_path):
        os.remove(db_path)

    print(f"Initializing schema at {db_path} ...")
    from database.models import DB_PATH, init_database

    init_database()
    assert DB_PATH == db_path, f"DB_PATH mismatch: expected {db_path}, got {DB_PATH}"

    import sqlite3

    conn = sqlite3.connect(db_path)
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    conn.close()

    missing = EXPECTED_TABLES - tables
    if missing:
        print(f"❌ Missing expected table(s): {sorted(missing)}")
        sys.exit(1)
    print(f"✅ All {len(EXPECTED_TABLES)} expected tables present ({len(tables)} total)")

    # Round-trip a real write + read through the actual DatabaseManager,
    # not just raw SQL, to catch issues in the ORM-ish layer too.
    from database.db_manager import db

    db.add_audit_log(action="ci_db_check", status="success", details="verify_db_init.py")
    rows = db.get_audit_log(limit=1, action="ci_db_check")
    assert len(rows) == 1, "Round-trip write/read through DatabaseManager failed"
    db.close_all_connections()
    print("✅ Read/write round-trip through DatabaseManager succeeded")
    print("✅ Database initialization verified")


if __name__ == "__main__":
    main()
