"""
HorusShield Attack Detector — Features 4, 5, 6
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Feature 4: DDoS Attack Detection
Feature 5: Port Scan Attack Detection
Feature 6: Brute Force Attack Detection

Rule-based detection with configurable thresholds.
"""

import threading
import time
import json

from database.db_manager import db
from utils.logger import get_logger
from utils.helpers import severity_to_number
from config import active_config as config

logger = get_logger("attack_detector", "attack")


class AttackDetector:
    """Detects network attacks using rule-based pattern analysis.

    Monitors packet analyzer data and applies detection rules for:
    - DDoS (high packet rate, SYN floods)
    - Port scanning (multiple ports probed)
    - Brute force (failed auth attempts)
    """

    def __init__(self, packet_analyzer, device_blocker=None, socketio=None):
        self.analyzer = packet_analyzer
        self.blocker = device_blocker
        self.socketio = socketio
        self._running = False
        self._detect_thread = None

        # Active attack tracking
        self.active_attacks = {}  # ip -> {type, start_time, packet_count, ...}
        self._attack_cooldown = {}  # ip -> timestamp (prevent duplicate alerts)
        self._cooldown_period = 60  # seconds between alerts for same IP

        # Detection thresholds from config
        self.ddos_pkt_threshold = config.DDOS_PACKET_THRESHOLD
        self.ddos_syn_threshold = config.DDOS_SYN_THRESHOLD
        self.ddos_window = config.DDOS_TIME_WINDOW
        self.portscan_port_threshold = config.PORTSCAN_PORT_THRESHOLD
        self.portscan_window = config.PORTSCAN_TIME_WINDOW
        self.bruteforce_threshold = config.BRUTEFORCE_ATTEMPT_THRESHOLD
        self.bruteforce_window = config.BRUTEFORCE_TIME_WINDOW
        self.bruteforce_ports = config.BRUTEFORCE_PORTS

    def start(self):
        """Start the attack detection engine."""
        if self._running:
            return

        self._running = True
        self._detect_thread = threading.Thread(
            target=self._detection_loop, daemon=True, name="AttackDetector"
        )
        self._detect_thread.start()

        db.add_log("engine", "Attack detector started", level="info", source="attack_detector")
        logger.info("Attack detector started")

    def stop(self):
        """Stop the attack detector."""
        self._running = False
        logger.info("Attack detector stopped")

    def _detection_loop(self):
        """Main detection loop — runs every 2 seconds."""
        while self._running:
            time.sleep(2)
            if not self._running:
                break

            try:
                self._detect_ddos()
                self._detect_port_scan()
                self._detect_brute_force()
                self._cleanup_expired_attacks()
            except Exception as e:
                logger.error(f"Detection loop error: {e}")

    # ══════════════════════════════════════
    # Feature 4: DDoS Detection
    # ══════════════════════════════════════

    def _detect_ddos(self):
        """Detect DDoS attacks based on packet rate and SYN flood patterns."""
        now = time.time()

        for ip, timestamps in self.analyzer.ip_timestamps.items():
            # Count packets in the detection window
            recent = [t for t in timestamps if t > now - self.ddos_window]
            pkt_rate = len(recent) / self.ddos_window if recent else 0

            syn_count = self.analyzer.ip_syn_counts.get(ip, 0)

            # Check thresholds
            is_ddos = False
            severity = "medium"
            details = {}

            if pkt_rate >= self.ddos_pkt_threshold:
                is_ddos = True
                severity = "critical" if pkt_rate >= self.ddos_pkt_threshold * 2 else "high"
                details["type"] = "volumetric"
                details["packets_per_sec"] = round(pkt_rate, 1)
                details["threshold"] = self.ddos_pkt_threshold

            elif syn_count >= self.ddos_syn_threshold:
                is_ddos = True
                severity = "critical" if syn_count >= self.ddos_syn_threshold * 2 else "high"
                details["type"] = "syn_flood"
                details["syn_count"] = syn_count
                details["threshold"] = self.ddos_syn_threshold

            if is_ddos and not self._in_cooldown(ip, "ddos"):
                self._register_attack(
                    attack_type="ddos",
                    source_ip=ip,
                    severity=severity,
                    confidence=min(1.0, pkt_rate / (self.ddos_pkt_threshold * 3)),
                    packet_count=len(recent),
                    details=details,
                )

    # ══════════════════════════════════════
    # Feature 5: Port Scan Detection
    # ══════════════════════════════════════

    def _detect_port_scan(self):
        """Detect port scanning based on unique port access patterns."""
        for ip, ports in self.analyzer.ip_port_access.items():
            unique_ports = len(ports)

            if unique_ports >= self.portscan_port_threshold:
                if not self._in_cooldown(ip, "port_scan"):
                    severity = "high" if unique_ports >= self.portscan_port_threshold * 2 else "medium"

                    self._register_attack(
                        attack_type="port_scan",
                        source_ip=ip,
                        severity=severity,
                        confidence=min(1.0, unique_ports / (self.portscan_port_threshold * 3)),
                        details={
                            "unique_ports_scanned": unique_ports,
                            "ports": sorted(list(ports))[:50],  # limit for storage
                            "threshold": self.portscan_port_threshold,
                        },
                    )

    # ══════════════════════════════════════
    # Feature 6: Brute Force Detection
    # ══════════════════════════════════════

    def _detect_brute_force(self):
        """Detect brute force attacks based on failed authentication attempts."""
        for ip, failed_count in self.analyzer.ip_failed_auths.items():
            if failed_count >= self.bruteforce_threshold:
                if not self._in_cooldown(ip, "brute_force"):
                    # Check which ports are being targeted
                    accessed_ports = self.analyzer.ip_port_access.get(ip, set())
                    targeted_services = [p for p in accessed_ports if p in self.bruteforce_ports]

                    severity = "critical" if failed_count >= self.bruteforce_threshold * 3 else "high"

                    self._register_attack(
                        attack_type="brute_force",
                        source_ip=ip,
                        severity=severity,
                        confidence=min(1.0, failed_count / (self.bruteforce_threshold * 5)),
                        details={
                            "failed_attempts": failed_count,
                            "targeted_ports": targeted_services,
                            "threshold": self.bruteforce_threshold,
                            "service_names": self._port_to_service(targeted_services),
                        },
                    )

    # ══════════════════════════════════════
    # Attack Registration & Management
    # ══════════════════════════════════════

    def _register_attack(self, attack_type, source_ip, severity="medium",
                          confidence=0.5, packet_count=0, bytes_total=0,
                          details=None, target_ip=None, target_port=None):
        """Register a detected attack in the database and create alerts."""

        # Store in database
        attack_id = db.add_attack(
            attack_type=attack_type,
            source_ip=source_ip,
            target_ip=target_ip,
            target_port=target_port,
            severity=severity,
            confidence=confidence,
            packet_count=packet_count,
            bytes_total=bytes_total,
            details=details,
            detected_by="engine",
        )

        # Create alert
        type_names = {
            "ddos": "DDoS Attack",
            "port_scan": "Port Scan",
            "brute_force": "Brute Force Attack",
        }
        attack_name = type_names.get(attack_type, attack_type.title())

        db.add_alert(
            alert_type="attack",
            title=f"🚨 {attack_name} Detected",
            message=(
                f"Attack Type: {attack_name}\n"
                f"Source IP: {source_ip}\n"
                f"Severity: {severity.upper()}\n"
                f"Confidence: {confidence:.0%}\n"
                f"Details: {json.dumps(details) if details else 'N/A'}"
            ),
            severity=severity,
            source="attack_detector",
            attack_id=attack_id,
            metadata={"source_ip": source_ip, "attack_type": attack_type, **({} if details is None else details)},
        )

        # Log
        db.add_log(
            "attack",
            f"{attack_name} from {source_ip} — severity: {severity}, confidence: {confidence:.0%}",
            level="critical" if severity in ("critical", "high") else "warning",
            source="attack_detector",
            ip_address=source_ip,
        )

        # Track active attack
        self.active_attacks[source_ip] = {
            "type": attack_type,
            "attack_id": attack_id,
            "severity": severity,
            "start_time": time.time(),
            "packet_count": packet_count,
        }

        # Set cooldown
        self._attack_cooldown[f"{source_ip}:{attack_type}"] = time.time()

        # Auto-block if configured
        if self.blocker and severity_to_number(severity) >= 4:  # high or critical
            device = db.get_device(ip_address=source_ip)
            if device:
                self.blocker.auto_block(
                    device['mac_address'],
                    ip_address=source_ip,
                    reason=f"Auto-blocked: {attack_name} detected",
                )

        # Emit to WebSocket
        if self.socketio:
            self.socketio.emit('attack_detected', {
                "attack_id": attack_id,
                "type": attack_type,
                "source_ip": source_ip,
                "severity": severity,
                "confidence": confidence,
                "details": details,
            })

        logger.critical(
            f"ATTACK DETECTED: {attack_name} from {source_ip} "
            f"[{severity}] confidence={confidence:.0%}"
        )

        return attack_id

    def _in_cooldown(self, ip, attack_type):
        """Check if an IP/attack type is in alert cooldown."""
        key = f"{ip}:{attack_type}"
        last_alert = self._attack_cooldown.get(key, 0)
        return (time.time() - last_alert) < self._cooldown_period

    def _cleanup_expired_attacks(self):
        """Clean up attacks that have stopped."""
        now = time.time()
        expired = []

        for ip, info in self.active_attacks.items():
            # If no recent packets from this IP, mark attack as mitigated
            recent = self.analyzer.ip_timestamps.get(ip, [])
            recent_count = len([t for t in recent if t > now - 30])

            if recent_count == 0 and now - info['start_time'] > 30:
                db.update_attack_status(info['attack_id'], 'mitigated', 'Attack ceased')
                expired.append(ip)
                logger.info(f"Attack from {ip} ceased — marked as mitigated")

        for ip in expired:
            del self.active_attacks[ip]

    def _port_to_service(self, ports):
        """Map port numbers to service names."""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 8080: "HTTP-Proxy",
        }
        return [services.get(p, f"Port-{p}") for p in ports]

    def get_active_attacks(self):
        """Get currently active attacks."""
        return dict(self.active_attacks)

    def get_attack_summary(self):
        """Get attack summary statistics."""
        stats = db.get_attack_stats(hours=24)
        active_count = db.get_active_attacks_count()

        return {
            "active_attacks": active_count,
            "total_24h": sum(s['count'] for s in stats),
            "by_type": stats,
            "currently_tracking": list(self.active_attacks.keys()),
        }


