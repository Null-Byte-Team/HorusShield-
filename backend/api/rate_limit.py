"""
HorusShield — Shared Rate Limiter
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Single flask-limiter instance, created unbound here and attached to the app
in app.py's create_app() (the standard flask-limiter app-factory pattern —
this avoids a circular import between app.py and every routes_*.py file
that wants to use @limiter.limit(...)).

All the actual numeric limits live in config.py (RATELIMIT_LOGIN, etc.) —
nothing here is a magic number.

Storage: in-memory by default (RATELIMIT_STORAGE_URI="memory://"), which
means limits reset on restart and don't share state across multiple
processes. That's an accepted tradeoff for HorusShield's current
single-process deployment model (see docs/ARCHITECTURE.md on why SQLite/
single-instance was chosen) — for a multi-process deployment, set
HORUS_RATELIMIT_STORAGE to a shared Redis URI instead.
"""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
