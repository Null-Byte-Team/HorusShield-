"""
HorusShield Device Detector — Features 2 & 3
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Feature 2: Detect new devices connecting to the network.
Feature 3: Identify unknown/unauthorized devices.
"""

import threading
import time
import json
from datetime import datetime

from engine.network_scanner import NetworkScanner
from database.db_manager import db
from utils.logger import get_logger
from utils.helpers import classify_device_type
from config import active_config as config

logger = get_logger("device_detector", "device")


class DeviceDetector:
    """Monitors the network for new and unknown devices.

    Periodically scans the network and compares found devices
    against the known device database.
    """

    def __init__(self, socketio=None):
        self.scanner = NetworkScanner()
        self.socketio = socketio
        self._running = False
        self._scan_thread = None
        self._interval = config.DEVICE_SCAN_INTERVAL
        self._known_macs = set()
        self._last_scan_results = []
        self._scan_count = 0

    def start(self):
        """Start the device detector background thread."""
        if self._running:
            logger.warning("Device detector already running")
            return

        self._running = True
        self._load_known_devices()

        self._scan_thread = threading.Thread(
            target=self._scan_loop, daemon=True, name="DeviceDetector"
        )
        self._scan_thread.start()

        db.add_log("engine", "Device detector started", level="info", source="device_detector")
        logger.info("Device detector started")

    def stop(self):
        """Stop the device detector."""
        self._running = False
        logger.info("Device detector stopped")

    def _load_known_devices(self):
        """Load known device MACs from database."""
        # Clear stale demo/fake devices on startup
        self._cleanup_stale_devices()
        devices = db.get_all_devices()
        self._known_macs = {d['mac_address'] for d in devices}
        logger.info(f"Loaded {len(self._known_macs)} known devices")

    def _cleanup_stale_devices(self):
        """Remove devices with obviously fake/demo MAC addresses.
        
        NOTE: synthetic 02:00:XX:XX:XX:XX MACs are from socket-scan fallback
        and represent legitimate discovered hosts without a resolvable MAC.
        Only remove truly fake demo devices with OTHER fake indicators.
        """
        try:
            all_devs = db.get_all_devices()
            removed = 0
            for dev in all_devs:
                mac = dev.get('mac_address','')
                hostname = dev.get('hostname','')
                vendor = dev.get('vendor','')
                is_gateway = dev.get('is_gateway', 0)
                
                should_remove = False
                
                # Only remove obvious demo/fake devices, NOT socket-scan devices
                
                # Remove completely empty MACs (shouldn't happen, but just in case)
                if mac == '':
                    should_remove = True
                # Remove obviously fake/demo MAC addresses
                elif mac.startswith('de:ad:be') or mac.startswith('ba:db:ad'):
                    should_remove = True
                # Remove obvious demo device patterns
                elif hostname in ('Workstation-Demo', 'Fake-Device', 'Demo-Host'):
                    should_remove = True
                # DO NOT remove synthetic socket-scan MACs like 02:00:AA:BB:CC:DD.
                # Those are deterministic placeholders for real discovered hosts.
                
                if should_remove and not is_gateway:
                    try:
                        with db.get_connection() as conn:
                            conn.execute('DELETE FROM devices WHERE id=?',(dev['id'],))
                        removed += 1
                    except Exception as e:
                        logger.error(f"Failed to delete device {dev['id']}: {e}")
            
            if removed > 0:
                logger.info(f"Cleaned {removed} obvious demo/fake devices from DB")
            else:
                logger.info("No stale devices to clean up")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

    def _scan_loop(self):
        """Main scanning loop."""
        # Initial scan immediately
        self._perform_scan()

        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            self._perform_scan()

    def _perform_scan(self):
        """Perform a network scan and process results."""
        try:
            self._scan_count += 1
            logger.info(f"Starting device scan #{self._scan_count}")

            # Perform ARP scan
            discovered = self.scanner.arp_scan()
            self._last_scan_results = discovered

            new_devices = []
            updated_devices = []

            for device in discovered:
                mac = device['mac_address']
                ip = device['ip_address']

                if mac in self._known_macs:
                    # Known device — update last_seen
                    db_device = db.get_device(mac_address=mac)
                    if db_device:
                        db.update_device(db_device['id'],
                                          ip_address=ip,
                                          last_seen=datetime.utcnow().isoformat(),
                                          last_activity='network_scan')
                        updated_devices.append(device)
                else:
                    # New device detected!
                    self._handle_new_device(device)
                    new_devices.append(device)
                    self._known_macs.add(mac)

            # Check for disappeared devices
            self._check_disappeared_devices(discovered)

            logger.info(
                f"Scan #{self._scan_count} complete: "
                f"{len(discovered)} found, {len(new_devices)} new, {len(updated_devices)} updated"
            )

        except Exception as e:
            logger.error(f"Device scan error: {e}")

    def _handle_new_device(self, device):
        """Handle a newly discovered device."""
        mac = device['mac_address']
        ip = device['ip_address']
        hostname = device.get('hostname', 'Unknown')
        vendor = device.get('vendor', 'Unknown')
        device_type = device.get('device_type', 'unknown')
        is_gateway = device.get('is_gateway', False)

        # Determine initial status
        status = 'trusted' if is_gateway else 'unknown'

        logger.info(f"New device detected: {hostname} ({ip}) MAC:{mac} - Status:{status}")

        # Port scan to gather more info
        try:
            open_ports = self.scanner.port_scan(ip, ports=[22, 80, 443, 8080, 3389, 5900, 9100])
            if not device_type or device_type == 'unknown':
                device_type = classify_device_type(hostname, vendor, open_ports)
        except Exception:
            open_ports = []

        # Add to database
        device_id = db.add_device(
            mac_address=mac,
            ip_address=ip,
            hostname=hostname,
            vendor=vendor,
            device_type=device_type,
            status=status,
        )
        logger.info(f"Device added to DB with ID {device_id}")

        # Update with additional info
        db.update_device(device_id,
                          open_ports=json.dumps(open_ports),
                          is_gateway=int(is_gateway))

        # Create alert for new device
        severity = 'info' if is_gateway else 'medium'
        alert_type = 'new_device' if status == 'unknown' else 'new_device'

        alert_title = f"New {'Gateway' if is_gateway else device_type.title()} Detected"
        alert_msg = (
            f"New device connected to the network:\n"
            f"IP: {ip}\n"
            f"MAC: {mac}\n"
            f"Hostname: {hostname}\n"
            f"Vendor: {vendor}\n"
            f"Type: {device_type}"
        )

        alert_id = db.add_alert(
            alert_type=alert_type,
            title=alert_title,
            message=alert_msg,
            severity=severity,
            source="device_detector",
            device_id=device_id,
            metadata={
                "mac": mac,
                "ip": ip,
                "hostname": hostname,
                "vendor": vendor,
                "device_type": device_type,
                "open_ports": open_ports,
            }
        )

        # Log
        db.add_log("device", f"New device detected: {mac} ({ip}) - {vendor}",
                    level="info" if is_gateway else "warning",
                    source="device_detector", ip_address=ip)

        # Handle unknown device (Feature 3)
        if status == 'unknown' and config.UNKNOWN_DEVICE_ALERT:
            self._handle_unknown_device(device_id, device)

        # Emit to WebSocket
        if self.socketio:
            self.socketio.emit('new_device', {
                "id": device_id,
                "mac": mac,
                "ip": ip,
                "hostname": hostname,
                "vendor": vendor,
                "device_type": device_type,
                "status": status,
                "alert_id": alert_id,
            })

        logger.info(f"New device: {mac} ({ip}) — {vendor} [{device_type}]")

    def _handle_unknown_device(self, device_id, device):
        """Handle an unknown/unauthorized device — Feature 3."""
        mac = device['mac_address']
        ip = device['ip_address']

        # Create a higher severity alert for unknown device
        db.add_alert(
            alert_type='unknown_device',
            title="⚠️ Unknown Device Detected",
            message=(
                f"An unrecognized device has joined the network.\n"
                f"IP: {ip}\n"
                f"MAC: {mac}\n"
                f"This device is not in the trusted device list.\n"
                f"Action: Review and trust or block this device."
            ),
            severity='high',
            source="device_detector",
            device_id=device_id,
            metadata={"mac": mac, "ip": ip, "action_required": True}
        )

        db.add_log("device", f"Unknown device alert: {mac} ({ip})",
                    level="warning", source="device_detector", ip_address=ip)

        # Emit warning
        if self.socketio:
            self.socketio.emit('unknown_device_alert', {
                "device_id": device_id,
                "mac": mac,
                "ip": ip,
            })

    def _check_disappeared_devices(self, current_devices):
        """Check for devices that have gone offline."""
        current_macs = {d['mac_address'] for d in current_devices}
        all_devices = db.get_all_devices()

        for device in all_devices:
            if device['mac_address'] not in current_macs and device['status'] != 'blocked':
                # Device might be offline — update last_activity
                db.update_device(device['id'], last_activity='offline')

    def trust_device(self, device_id):
        """Mark a device as trusted."""
        db.update_device(device_id, status='trusted')
        device = db.get_device(device_id=device_id)
        if device:
            db.add_log("device", f"Device trusted: {device['mac_address']} ({device['ip_address']})",
                        level="info", source="device_detector")
        logger.info(f"Device {device_id} marked as trusted")

    def flag_device(self, device_id):
        """Mark a device as suspicious."""
        db.update_device(device_id, status='suspicious')
        db.add_alert(
            alert_type='suspicious_device',
            title="Device Flagged as Suspicious",
            message=f"Device ID {device_id} has been flagged for investigation.",
            severity='high',
            source="device_detector",
            device_id=device_id,
        )
        logger.warning(f"Device {device_id} flagged as suspicious")

    def manual_scan(self):
        """Trigger an immediate network scan."""
        logger.info("Manual device scan triggered")
        self._perform_scan()
        return self._last_scan_results

    def get_last_scan_results(self):
        """Get results from the last scan."""
        return self._last_scan_results

    def get_scan_count(self):
        """Get total number of scans performed."""
        return self._scan_count
