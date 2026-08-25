"""
HorusShield Device Blocker — Feature 16
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Automatic and manual device blocking functionality.
Integrates with Windows Firewall and iptables.
"""

import subprocess
import platform
import threading

from database.db_manager import db
from utils.logger import get_logger

logger = get_logger("device_blocker", "engine")


class DeviceBlocker:
    """Manages device blocking via firewall rules.

    Supports:
    - Manual blocking/unblocking by MAC or IP
    - Automatic blocking triggered by attack detection
    - Temporary blocks with expiration
    - Lockdown mode integration
    """

    def __init__(self, socketio=None):
        self.socketio = socketio
        self._platform = platform.system().lower()
        self._lock = threading.Lock()

    def block_device(self, mac_address, ip_address=None, reason="Manual block",
                     blocked_by="manual", is_permanent=False, duration_minutes=0):
        """Block a device from the network.

        Args:
            mac_address: Device MAC address
            ip_address: Device IP address (needed for firewall rules)
            reason: Reason for blocking
            blocked_by: Who/what triggered the block
            is_permanent: Whether this is a permanent block
            duration_minutes: Duration for temporary blocks (0=permanent)
        """
        with self._lock:
            # Check if already blocked
            if db.is_blocked(mac_address=mac_address):
                logger.warning(f"Device {mac_address} is already blocked")
                return False

            # Add to database
            db.block_device(
                mac_address=mac_address,
                ip_address=ip_address,
                reason=reason,
                blocked_by=blocked_by,
                is_permanent=is_permanent,
                duration_minutes=duration_minutes,
            )

            # Apply firewall rule
            if ip_address:
                success = self._apply_firewall_block(ip_address)
            else:
                success = True  # MAC-only block (database level)

            # Create alert
            db.add_alert(
                alert_type="system",
                title=f"🚫 Device Blocked",
                message=(
                    f"Device has been blocked from the network.\n"
                    f"MAC: {mac_address}\n"
                    f"IP: {ip_address or 'N/A'}\n"
                    f"Reason: {reason}\n"
                    f"Blocked by: {blocked_by}\n"
                    f"Duration: {'Permanent' if is_permanent else f'{duration_minutes} minutes' if duration_minutes else 'Until manual unblock'}"
                ),
                severity="high",
                source="device_blocker",
                metadata={
                    "mac": mac_address,
                    "ip": ip_address,
                    "reason": reason,
                    "blocked_by": blocked_by,
                }
            )

            db.add_log("device", f"Blocked device: {mac_address} ({ip_address}) — {reason}",
                        level="warning", source="device_blocker", ip_address=ip_address)
            db.add_audit_log(
                action="device_blocked", username=blocked_by, ip_address=ip_address or "",
                details=f"mac={mac_address} reason={reason} permanent={is_permanent}",
            )

            # Emit to WebSocket
            if self.socketio:
                self.socketio.emit('device_blocked', {
                    "mac": mac_address,
                    "ip": ip_address,
                    "reason": reason,
                    "blocked_by": blocked_by,
                })

            logger.warning(f"Device blocked: {mac_address} ({ip_address}) — {reason}")
            return success

    def unblock_device(self, mac_address, ip_address=None):
        """Unblock a previously blocked device."""
        with self._lock:
            # Get IP if not provided
            if not ip_address:
                device = db.get_device(mac_address=mac_address)
                if device:
                    ip_address = device['ip_address']

            # Remove from database
            db.unblock_device(mac_address)

            # Remove firewall rule
            if ip_address:
                self._remove_firewall_block(ip_address)

            db.add_log("device", f"Unblocked device: {mac_address} ({ip_address})",
                        level="info", source="device_blocker", ip_address=ip_address)
            db.add_audit_log(
                action="device_unblocked", ip_address=ip_address or "",
                details=f"mac={mac_address}",
            )

            # Emit to WebSocket
            if self.socketio:
                self.socketio.emit('device_unblocked', {
                    "mac": mac_address,
                    "ip": ip_address,
                })

            logger.info(f"Device unblocked: {mac_address} ({ip_address})")
            return True

    def auto_block(self, mac_address, ip_address=None, reason="Auto-blocked by attack detector"):
        """Automatically block a device (triggered by attack detection)."""
        logger.warning(f"Auto-blocking device: {mac_address} ({ip_address})")
        return self.block_device(
            mac_address=mac_address,
            ip_address=ip_address,
            reason=reason,
            blocked_by="auto",
            duration_minutes=30,  # Default 30 min auto-block
        )

    def _apply_firewall_block(self, ip_address):
        """Apply a firewall rule to block an IP address."""
        try:
            if self._platform == "windows":
                # Windows Firewall (netsh)
                rule_name = f"HorusShield_Block_{ip_address.replace('.', '_')}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip_address}",
                    "enable=yes"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    logger.info(f"Firewall rule added for {ip_address}")
                    return True
                else:
                    logger.error(f"Failed to add firewall rule: {result.stderr}")
                    return False

            elif self._platform == "linux":
                # iptables
                cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    logger.info(f"iptables rule added for {ip_address}")
                    return True
                else:
                    logger.error(f"Failed to add iptables rule: {result.stderr}")
                    return False
            else:
                logger.warning(f"Firewall blocking not supported on {self._platform}")
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"Firewall command timed out for {ip_address}")
            return False
        except FileNotFoundError:
            logger.error("Firewall command not found — running without admin privileges?")
            return False
        except Exception as e:
            logger.error(f"Firewall error: {e}")
            return False

    def _remove_firewall_block(self, ip_address):
        """Remove a firewall block rule."""
        try:
            if self._platform == "windows":
                rule_name = f"HorusShield_Block_{ip_address.replace('.', '_')}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ]
                subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                logger.info(f"Firewall rule removed for {ip_address}")

            elif self._platform == "linux":
                cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                logger.info(f"iptables rule removed for {ip_address}")

        except Exception as e:
            logger.error(f"Error removing firewall rule: {e}")

    def block_all_except_whitelist(self, whitelist_ips):
        """Block all traffic except from whitelisted IPs (for lockdown mode)."""
        logger.critical("Activating full network block (LOCKDOWN)")
        try:
            if self._platform == "windows":
                # Block all inbound
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=HorusShield_Lockdown_BlockAll",
                    "dir=in", "action=block", "remoteip=any", "enable=yes"
                ], capture_output=True, timeout=10)

                # Allow whitelisted IPs
                for ip in whitelist_ips:
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=HorusShield_Lockdown_Allow_{ip.replace('.', '_')}",
                        "dir=in", "action=allow", f"remoteip={ip}", "enable=yes"
                    ], capture_output=True, timeout=10)

            elif self._platform == "linux":
                subprocess.run(["iptables", "-P", "INPUT", "DROP"], capture_output=True, timeout=10)
                for ip in whitelist_ips:
                    subprocess.run(
                        ["iptables", "-A", "INPUT", "-s", ip, "-j", "ACCEPT"],
                        capture_output=True, timeout=10
                    )
                # Always allow localhost
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                    capture_output=True, timeout=10
                )

            return True
        except Exception as e:
            logger.error(f"Lockdown block error: {e}")
            return False

    def remove_all_blocks(self):
        """Remove all HorusShield firewall rules."""
        logger.info("Removing all HorusShield firewall rules")
        try:
            if self._platform == "windows":
                # Remove only HorusShield rules (wildcard match via name prefix)
                # Note: netsh delete rule name=all deletes all rules. 
                # To delete specifically, we can use the names we generated.
                blocked = db.get_blocked_devices()
                for dev in blocked:
                    if dev.get('ip_address'):
                        self._remove_firewall_block(dev['ip_address'])
                
                # Also remove lockdown rules
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    "name=HorusShield_Lockdown_BlockAll"
                ], capture_output=True, timeout=10)

            elif self._platform == "linux":
                # Instead of flushing everything, we should ideally have a HORUS chain.
                # For now, just unblock specific IPs found in DB.
                blocked = db.get_blocked_devices()
                for dev in blocked:
                    if dev.get('ip_address'):
                        self._remove_firewall_block(dev['ip_address'])
                subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], capture_output=True, timeout=10)

            # Clear database blocks
            blocked = db.get_blocked_devices()
            for device in blocked:
                db.unblock_device(device['mac_address'])

            return True
        except Exception as e:
            logger.error(f"Error removing all blocks: {e}")
            return False

    def get_blocked_list(self):
        """Get list of currently blocked devices."""
        return db.get_blocked_devices()

    def restore_blocks(self):
        """Re-apply firewall rules for every device the database still records
        as blocked. Call this once at application startup — OS-level firewall
        rules do not automatically survive every environment (e.g. a fresh
        container, a flushed iptables ruleset, or a reinstalled Windows
        Firewall profile), so without this step a device could be "blocked"
        in HorusShield's database while actually being reachable on the wire.

        This is idempotent: re-adding a rule that already exists just fails
        silently for that one rule (logged at debug level) and continues.
        """
        blocked = db.get_blocked_devices()
        restored, skipped = 0, 0
        for device in blocked:
            ip = device.get("ip_address")
            if not ip:
                skipped += 1
                continue
            if self._apply_firewall_block(ip):
                restored += 1
            else:
                skipped += 1
        if blocked:
            logger.info(f"Startup firewall reconciliation: {restored} rule(s) restored, {skipped} skipped")
        return {"restored": restored, "skipped": skipped, "total": len(blocked)}

    def is_device_blocked(self, mac_address=None, ip_address=None):
        """Check if a device is blocked."""
        return db.is_blocked(mac_address=mac_address, ip_address=ip_address)
