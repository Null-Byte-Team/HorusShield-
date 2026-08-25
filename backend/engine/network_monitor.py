"""
HorusShield Network Monitor — Feature 1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Real-time network traffic monitoring using Scapy.
Runs as a background thread capturing and analyzing packets.
"""

import threading
import time
from datetime import datetime

from engine.packet_analyzer import PacketAnalyzer
from database.db_manager import db
from utils.logger import get_logger
from config import active_config as config

logger = get_logger("network_monitor", "network")


class NetworkMonitor:
    """Real-time network monitoring engine.

    Captures packets using Scapy, analyzes them through the PacketAnalyzer,
    and stores periodic traffic snapshots in the database.
    """

    def __init__(self, socketio=None):
        self.analyzer = PacketAnalyzer(buffer_size=config.PACKET_BUFFER_SIZE)
        self.socketio = socketio
        self._running = False
        self._capture_thread = None
        self._snapshot_thread = None
        self._interface = config.MONITOR_INTERFACE
        self._interval = config.MONITOR_INTERVAL

        # Real-time stats
        self._in_fallback_mode = False
        self.current_stats = {
            "packets_per_sec": 0,
            "bytes_per_sec": 0,
            "bandwidth_mbps": 0,
            "download_mbps": 0,
            "upload_mbps": 0,
            "active_connections": 0,
            "protocol_distribution": {"tcp": 0, "udp": 0, "icmp": 0, "other": 0},
        }

    def start(self):
        """Start the network monitor."""
        if self._running:
            logger.warning("Network monitor already running")
            return

        self._running = True
        logger.info("Starting network monitor")

        # Start packet capture thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="PacketCapture"
        )
        self._capture_thread.start()

        # Start snapshot thread
        self._snapshot_thread = threading.Thread(
            target=self._snapshot_loop, daemon=True, name="TrafficSnapshot"
        )
        self._snapshot_thread.start()

        db.add_log("engine", "Network monitor started", level="info", source="network_monitor")
        logger.info("Network monitor started successfully")

    def stop(self):
        """Stop the network monitor."""
        self._running = False
        logger.info("Stopping network monitor")
        db.add_log("engine", "Network monitor stopped", level="info", source="network_monitor")

    def is_running(self):
        """Check if the monitor is running."""
        return self._running

    def _capture_loop(self):
        """Main packet capture loop using Scapy."""
        try:
            from scapy.all import sniff, conf
            conf.verb = 0

            logger.info(f"Starting packet capture on interface: {self._interface or 'auto'}")

            def _process_packet(packet):
                if not self._running:
                    return
                self.analyzer.analyze_packet(packet)

            while self._running:
                try:
                    sniff(
                        iface=self._interface,
                        prn=_process_packet,
                        store=False,
                        timeout=5,
                        count=0,
                    )
                except Exception as e:
                    if self._running:
                        error_msg = str(e)
                        logger.error(f"Capture error: {error_msg}")
                        
                        if (
                            "winpcap" in error_msg.lower()
                            or "pcap" in error_msg.lower()
                            or "permission" in error_msg.lower()
                            or "operation not permitted" in error_msg.lower()
                        ):
                            logger.warning("Packet capture unavailable. Falling back to system metrics mode.")
                            self._in_fallback_mode = True
                            self._system_metrics_loop()
                            break
                            
                        time.sleep(2)

        except ImportError:
            logger.warning("Scapy not available — packet capture disabled")
            logger.info("Running in monitoring-only mode (system metrics)")
            self._system_metrics_loop()
        except Exception as e:
            logger.warning(f"Packet capture unavailable at startup. Falling back to system metrics mode: {e}")
            self._in_fallback_mode = True
            self._system_metrics_loop()

    def _system_metrics_loop(self):
        """Fallback: monitor system-level network metrics using psutil."""
        try:
            import psutil
            prev_io = psutil.net_io_counters()
            prev_time = time.time()

            while self._running:
                time.sleep(self._interval)
                if not self._running:
                    break

                curr_io = psutil.net_io_counters()
                curr_time = time.time()
                elapsed = curr_time - prev_time

                if elapsed > 0:
                    bytes_in = curr_io.bytes_recv - prev_io.bytes_recv
                    bytes_out = curr_io.bytes_sent - prev_io.bytes_sent
                    pkts_in = curr_io.packets_recv - prev_io.packets_recv
                    pkts_out = curr_io.packets_sent - prev_io.packets_sent

                    self.current_stats = {
                        "packets_per_sec": (pkts_in + pkts_out) / elapsed,
                        "bytes_per_sec": (bytes_in + bytes_out) / elapsed,
                        "packets_in": pkts_in,
                        "packets_out": pkts_out,
                        "bytes_in": bytes_in,
                        "bytes_out": bytes_out,
                        "bandwidth_mbps": ((bytes_in + bytes_out) * 8) / (elapsed * 1_000_000),
                        "download_mbps": (bytes_in * 8) / (elapsed * 1_000_000),
                        "upload_mbps": (bytes_out * 8) / (elapsed * 1_000_000),
                        "active_connections": len(psutil.net_connections()),
                        "timestamp": datetime.utcnow().isoformat(),
                    }

                    # Store snapshot
                    db.add_traffic_snapshot(
                        packets_in=pkts_in,
                        packets_out=pkts_out,
                        bytes_in=bytes_in,
                        bytes_out=bytes_out,
                        bandwidth_mbps=self.current_stats["bandwidth_mbps"],
                        active_connections=self.current_stats["active_connections"],
                    )

                    # Emit to WebSocket
                    if self.socketio:
                        self.socketio.emit('traffic_update', self.current_stats)

                prev_io = curr_io
                prev_time = curr_time

        except ImportError:
            logger.warning("psutil not available — no monitoring possible")
        except Exception as e:
            logger.error(f"System metrics loop error: {e}")

    def _snapshot_loop(self):
        """Periodically take traffic snapshots and emit to dashboard."""
        while self._running:
            time.sleep(self._interval)
            if self._in_fallback_mode:
                continue  # _system_metrics_loop handles this
            if not self._running:
                break

            try:
                snapshot = self.analyzer.get_snapshot()
                self.current_stats = {
                    "packets_per_sec": snapshot.get("packets_per_sec", 0),
                    "bytes_per_sec": snapshot.get("bytes_per_sec", 0),
                    "packets_in": snapshot.get("packets_in", 0),
                    "packets_out": snapshot.get("packets_out", 0),
                    "bytes_in": snapshot.get("bytes_in", 0),
                    "bytes_out": snapshot.get("bytes_out", 0),
                    "bandwidth_mbps": snapshot.get("bandwidth_mbps", 0),
                    "download_mbps": snapshot.get("download_mbps", 0),
                    "upload_mbps": snapshot.get("upload_mbps", 0),
                    "active_connections": snapshot.get("active_connections", 0),
                    "protocol_distribution": {
                        "tcp": snapshot.get("tcp_count", 0),
                        "udp": snapshot.get("udp_count", 0),
                        "icmp": snapshot.get("icmp_count", 0),
                        "other": snapshot.get("other_count", 0),
                    },
                    "unique_src_ips": snapshot.get("unique_src_ips", 0),
                    "unique_dst_ips": snapshot.get("unique_dst_ips", 0),
                    "syn_count": snapshot.get("syn_count", 0),
                    "timestamp": snapshot.get("timestamp", datetime.utcnow().isoformat()),
                }

                # Store in database
                db.add_traffic_snapshot(**{k: v for k, v in snapshot.items()
                                           if k not in ('timestamp', 'packets_per_sec', 'bytes_per_sec')})

                # Emit to dashboard via WebSocket
                if self.socketio:
                    self.socketio.emit('traffic_update', self.current_stats)

            except Exception as e:
                logger.error(f"Snapshot error: {e}")

    def get_current_stats(self):
        """Get current monitoring statistics."""
        return self.current_stats

    def get_traffic_history(self, minutes=60):
        """Get traffic history from database."""
        return db.get_traffic_history(minutes=minutes)

    def get_analyzer(self):
        """Get the packet analyzer instance."""
        return self.analyzer

    def get_live_or_latest_stats(self):
        """Return the freshest live stats, falling back to the latest DB snapshot."""
        stats = dict(self.current_stats or {})
        has_live_signal = any(
            (stats.get(key) or 0) > 0
            for key in ("packets_per_sec", "bandwidth_mbps", "download_mbps", "upload_mbps")
        )
        if has_live_signal:
            stats.setdefault("timestamp", datetime.utcnow().isoformat())
            return stats

        latest = db.get_latest_traffic() or {}
        if not latest:
            stats.setdefault("timestamp", datetime.utcnow().isoformat())
            return stats

        interval = max(self._interval, 1)
        bytes_in = latest.get("bytes_in", 0) or 0
        bytes_out = latest.get("bytes_out", 0) or 0
        packets_in = latest.get("packets_in", 0) or 0
        packets_out = latest.get("packets_out", 0) or 0
        return {
            "packets_in": packets_in,
            "packets_out": packets_out,
            "packets_per_sec": (packets_in + packets_out) / interval,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "bytes_per_sec": (bytes_in + bytes_out) / interval,
            "bandwidth_mbps": latest.get("bandwidth_mbps", 0) or ((bytes_in + bytes_out) * 8) / (interval * 1_000_000),
            "download_mbps": (bytes_in * 8) / (interval * 1_000_000),
            "upload_mbps": (bytes_out * 8) / (interval * 1_000_000),
            "active_connections": latest.get("active_connections", 0) or 0,
            "protocol_distribution": {
                "tcp": latest.get("tcp_count", 0) or 0,
                "udp": latest.get("udp_count", 0) or 0,
                "icmp": latest.get("icmp_count", 0) or 0,
                "other": latest.get("other_count", 0) or 0,
            },
            "timestamp": latest.get("timestamp") or datetime.utcnow().isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# REST Blueprint  →  GET /api/traffic/live
# Allows the UI (and any REST client) to poll the current live stats without
# waiting for a WebSocket push.  The route is registered in app.py.
# Monitor instance is fetched from app.extensions (no global coupling).
# ─────────────────────────────────────────────────────────────────────────────
from flask import Blueprint, jsonify, current_app

traffic_bp = Blueprint("traffic", __name__)


@traffic_bp.route("/live", methods=["GET"])
def get_live_traffic():
    """Return the most-recent live traffic snapshot from the running monitor."""
    monitor = current_app.extensions.get("monitor")

    if monitor is None:
        latest = db.get_latest_traffic()
        if latest:
            interval = max(config.MONITOR_INTERVAL, 1)
            stats = {
                "packets_in":         latest.get("packets_in", 0) or 0,
                "packets_out":        latest.get("packets_out", 0) or 0,
                "packets_per_sec":    ((latest.get("packets_in", 0) or 0) + (latest.get("packets_out", 0) or 0)) / interval,
                "bytes_in":           latest.get("bytes_in", 0) or 0,
                "bytes_out":          latest.get("bytes_out", 0) or 0,
                "bytes_per_sec":      ((latest.get("bytes_in", 0) or 0) + (latest.get("bytes_out", 0) or 0)) / interval,
                "bandwidth_mbps":     latest.get("bandwidth_mbps", 0) or 0,
                "download_mbps":      ((latest.get("bytes_in", 0) or 0) * 8) / (interval * 1_000_000),
                "upload_mbps":        ((latest.get("bytes_out", 0) or 0) * 8) / (interval * 1_000_000),
                "active_connections": latest.get("active_connections", 0) or 0,
                "protocol_distribution": {
                    "tcp":   latest.get("tcp_count", 0) or 0,
                    "udp":   latest.get("udp_count", 0) or 0,
                    "icmp":  latest.get("icmp_count", 0) or 0,
                    "other": latest.get("other_count", 0) or 0,
                },
                "timestamp": latest.get("timestamp") or datetime.utcnow().isoformat(),
            }
            return jsonify(stats)
        return jsonify({"error": "Monitor not started yet"}), 503

    stats = monitor.get_live_or_latest_stats()
    return jsonify(stats)
