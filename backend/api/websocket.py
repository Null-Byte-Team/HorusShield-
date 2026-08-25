"""
HorusShield WebSocket — Fixed async_mode for PyInstaller EXE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Root-cause fix: async_mode MUST be set inside SocketIO() constructor.
Setting ws.sio.async_mode AFTER init raises ValueError in engineio.
"""
from datetime import datetime
from flask_socketio import SocketIO, emit
from database.db_manager import db
from utils.logger import get_logger

logger = get_logger("websocket", "api")


def _make_socketio(app):
    """
    Try async_mode='threading' first (works in frozen EXE without eventlet).
    Fall back to no explicit mode if threading driver is missing.
    """
    for mode in ('threading', None):
        try:
            kwargs = dict(
                cors_allowed_origins="*",
                ping_timeout=120,
                ping_interval=25,
                logger=False,
                engineio_logger=False,
            )
            if mode:
                kwargs['async_mode'] = mode
            sio = SocketIO(app, **kwargs)
            logger.info(f"SocketIO created — async_mode={mode or 'auto'}")
            return sio
        except (ValueError, Exception) as e:
            logger.warning(f"SocketIO mode '{mode}' failed: {e}")
    raise RuntimeError("Failed to initialize SocketIO with any async_mode")


class HorusSocket:
    def __init__(self, app):
        self.sio = _make_socketio(app)
        self._setup_handlers()

    def _setup_handlers(self):
        sio = self.sio

        @sio.on('connect')
        def on_connect():
            logger.info("Client connected")
            emit('connection_response', {'data': 'Connected to HorusShield 2.0'})

        @sio.on('request_initial_data')
        def on_initial_data():
            try:
                emit('initial_dashboard', db.get_dashboard_stats())
                emit('initial_devices',   db.get_all_devices())
                emit('initial_attacks',   db.get_attacks(limit=20))
                score = db.get_latest_score()
                emit('initial_score', score if score else {"total_score": 85, "trend": "stable"})
                emit('initial_alerts', db.get_alerts(limit=20))
                # Send live traffic snapshot if monitor is running
                try:
                    from flask import current_app
                    monitor = current_app.extensions.get("monitor")
                    if monitor is not None:
                        stats = dict(monitor.get_current_stats())
                        stats.setdefault("timestamp", datetime.utcnow().isoformat())
                        emit('initial_traffic', stats)
                except Exception:
                    pass
                logger.info("Initial data sent to client")
            except Exception as e:
                logger.error(f"Initial data error: {e}")

        @sio.on('ping_horus')
        def on_ping():
            emit('pong_horus', {'timestamp': datetime.now().isoformat()})

        @sio.on('disconnect')
        def on_disconnect():
            logger.info("Client disconnected")

    def broadcast(self, event, data):
        self.sio.emit(event, data)
