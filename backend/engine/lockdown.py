"""
HorusShield Emergency Lockdown — Feature 17
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Emergency lockdown mode that blocks all non-whitelisted traffic.
Activates Anubis/emergency mode on the dashboard.
"""

import threading
from datetime import datetime

from database.db_manager import db
from utils.logger import get_logger
from config import active_config as config

logger = get_logger("lockdown", "engine")


class LockdownManager:
    """Emergency lockdown mode manager.

    When activated:
    - Blocks all non-whitelisted network traffic
    - Activates emergency/Anubis mode on dashboard
    - Logs all activity during lockdown
    - Sends critical alerts
    - Can be activated manually or automatically
    """

    def __init__(self, device_blocker=None, socketio=None):
        self.blocker = device_blocker
        self.socketio = socketio
        self._active = False
        self._activated_at = None
        self._activated_by = None
        self._reason = ""
        self._whitelist = config.LOCKDOWN_WHITELIST.copy()
        self._lock = threading.Lock()

        # Check if lockdown was active before restart
        self._check_persisted_state()

    def _check_persisted_state(self):
        """Check if lockdown was active before a restart, and if so actually
        re-apply the network block — not just restore the in-memory flag.

        Previously this only set `self._active = True` from the persisted
        setting, which made the dashboard *report* lockdown as active after a
        restart while the underlying firewall rules were never re-applied
        (device_blocker.restore_blocks(), called separately at app startup,
        only restores individually-blocked devices — it doesn't know about
        the lockdown-wide "block everything except whitelist" rule). That
        left a real gap between reported and actual state.
        """
        try:
            state = db.get_setting('lockdown_active', 'false')
            if state != 'true':
                return
            logger.warning("Lockdown state was active before restart — reapplying network block")
            self._active = True
            self._activated_at = datetime.utcnow()
            self._activated_by = "restored"
            self._reason = "Persisted from previous session"

            if self.blocker:
                from utils.helpers import get_gateway_ip, get_local_ip
                gateway = get_gateway_ip()
                local = get_local_ip()
                whitelist = self._whitelist + [local]
                if gateway:
                    whitelist.append(gateway)
                self.blocker.block_all_except_whitelist(whitelist)

            db.add_audit_log(
                action="emergency_mode_restored", status="success",
                details="Lockdown was active at last shutdown; firewall block re-applied on startup",
            )
        except Exception as e:
            logger.error(f"Failed to restore persisted lockdown state: {e}")

    def activate(self, reason="Manual activation", activated_by="manual"):
        """Activate emergency lockdown mode.

        Args:
            reason: Why lockdown was activated
            activated_by: Who/what triggered it (manual, ai, auto)
        """
        with self._lock:
            if self._active:
                logger.warning("Lockdown already active")
                return {"status": "already_active"}

            self._active = True
            self._activated_at = datetime.utcnow()
            self._activated_by = activated_by
            self._reason = reason

            logger.critical(f"🔒 EMERGENCY LOCKDOWN ACTIVATED — Reason: {reason}")

            # Persist state
            db.set_setting('lockdown_active', 'true')
            db.set_setting('theme', 'emergency')

            # Apply network blocks
            if self.blocker:
                # Get gateway IP for whitelist
                from utils.helpers import get_gateway_ip, get_local_ip
                gateway = get_gateway_ip()
                local = get_local_ip()
                whitelist = self._whitelist + [local]
                if gateway:
                    whitelist.append(gateway)

                self.blocker.block_all_except_whitelist(whitelist)

            # Block all unknown/suspicious devices
            devices = db.get_all_devices()
            blocked_count = 0
            for device in devices:
                if device['status'] not in ('trusted',) and device['ip_address'] not in self._whitelist:
                    if self.blocker:
                        self.blocker.block_device(
                            device['mac_address'],
                            ip_address=device['ip_address'],
                            reason=f"Lockdown: {reason}",
                            blocked_by="lockdown",
                        )
                    blocked_count += 1

            # Create critical alert
            db.add_alert(
                alert_type="lockdown",
                title="🔒 EMERGENCY LOCKDOWN ACTIVATED",
                message=(
                    f"Emergency lockdown mode has been activated.\n"
                    f"Reason: {reason}\n"
                    f"Activated by: {activated_by}\n"
                    f"Devices blocked: {blocked_count}\n"
                    f"All non-whitelisted traffic is now blocked.\n"
                    f"Only trusted devices can communicate."
                ),
                severity="critical",
                source="lockdown",
                metadata={
                    "reason": reason,
                    "activated_by": activated_by,
                    "devices_blocked": blocked_count,
                    "whitelist": self._whitelist,
                }
            )

            # Log
            db.add_log("system", f"LOCKDOWN ACTIVATED: {reason}",
                        level="critical", source="lockdown")
            db.add_audit_log(
                action="emergency_mode_enabled", username=activated_by, status="success",
                details=f"reason={reason} devices_blocked={blocked_count}",
            )

            # Emit to WebSocket
            if self.socketio:
                self.socketio.emit('lockdown_activated', {
                    "active": True,
                    "reason": reason,
                    "activated_by": activated_by,
                    "activated_at": self._activated_at.isoformat(),
                    "devices_blocked": blocked_count,
                })
                # Switch dashboard to emergency mode
                self.socketio.emit('mode_change', {"mode": "emergency"})

            return {
                "status": "activated",
                "reason": reason,
                "devices_blocked": blocked_count,
                "activated_at": self._activated_at.isoformat(),
            }

    def deactivate(self, deactivated_by="manual"):
        """Deactivate emergency lockdown mode."""
        with self._lock:
            if not self._active:
                logger.info("Lockdown not active")
                return {"status": "not_active"}

            duration = (datetime.utcnow() - self._activated_at).total_seconds() if self._activated_at else 0

            logger.info(f"🔓 LOCKDOWN DEACTIVATED after {duration:.0f}s")

            self._active = False

            # Persist state
            db.set_setting('lockdown_active', 'false')
            db.set_setting('theme', 'dark')

            # Remove network blocks
            if self.blocker:
                self.blocker.remove_all_blocks()

            # Restore blocked devices that were blocked by lockdown
            blocked = db.get_blocked_devices()
            restored = 0
            for device in blocked:
                if device.get('blocked_by') == 'lockdown':
                    if self.blocker:
                        self.blocker.unblock_device(device['mac_address'])
                    restored += 1

            # Create alert
            db.add_alert(
                alert_type="lockdown",
                title="🔓 Lockdown Deactivated",
                message=(
                    f"Emergency lockdown has been deactivated.\n"
                    f"Duration: {duration:.0f} seconds\n"
                    f"Devices restored: {restored}\n"
                    f"Network traffic is returning to normal."
                ),
                severity="high",
                source="lockdown",
                metadata={
                    "duration_seconds": duration,
                    "devices_restored": restored,
                    "deactivated_by": deactivated_by,
                }
            )

            db.add_log("system", f"LOCKDOWN DEACTIVATED after {duration:.0f}s",
                        level="info", source="lockdown")
            db.add_audit_log(
                action="emergency_mode_disabled", username=deactivated_by, status="success",
                details=f"duration_seconds={duration:.0f} devices_restored={restored}",
            )

            # Emit to WebSocket
            if self.socketio:
                self.socketio.emit('lockdown_deactivated', {
                    "active": False,
                    "duration": duration,
                    "devices_restored": restored,
                })
                self.socketio.emit('mode_change', {"mode": "dark"})

            self._activated_at = None
            self._activated_by = None
            self._reason = ""

            return {
                "status": "deactivated",
                "duration_seconds": duration,
                "devices_restored": restored,
            }

    def is_active(self):
        """Check if lockdown is currently active."""
        return self._active

    def get_status(self):
        """Get current lockdown status."""
        return {
            "active": self._active,
            "activated_at": self._activated_at.isoformat() if self._activated_at else None,
            "activated_by": self._activated_by,
            "reason": self._reason,
            "duration_seconds": (
                (datetime.utcnow() - self._activated_at).total_seconds()
                if self._activated_at else 0
            ),
            "whitelist": self._whitelist,
        }

    def add_to_whitelist(self, ip_address):
        """Add an IP to the lockdown whitelist."""
        if ip_address not in self._whitelist:
            self._whitelist.append(ip_address)
            logger.info(f"Added {ip_address} to lockdown whitelist")

    def remove_from_whitelist(self, ip_address):
        """Remove an IP from the lockdown whitelist."""
        if ip_address in self._whitelist:
            self._whitelist.remove(ip_address)
            logger.info(f"Removed {ip_address} from lockdown whitelist")
