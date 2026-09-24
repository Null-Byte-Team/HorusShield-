"""
HorusShield Global Threat Map — Feature 12
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Visualizing the origin and frequency of incoming cyber threats.
"""

import random
from database.db_manager import db
from utils.logger import get_logger

logger = get_logger("threat_map", "services")

class ThreatMapService:
    """Service to track and map global attack origins.
    
    Uses GeoIP lookup to find the origin of attack source IPs
    and provides data for the global threat visualizer.
    """
    
    def __init__(self):
        self.geo_cache = {}

    def is_local_or_private(self, ip):
        """Check if an IP is localhost or RFC1918 private."""
        if not ip:
            return True
        s = str(ip).strip()
        return (
            s.startswith("127.") or
            s.startswith("192.168.") or
            s.startswith("10.") or
            s.startswith("172.16.") or
            s.startswith("172.17.") or
            s.startswith("172.18.") or
            s.startswith("172.19.") or
            s.startswith("172.2") or
            s.startswith("172.30.") or
            s.startswith("172.31.") or
            s == "::1" or
            s.startswith("fe80:") or
            s.startswith("0.0.0.0")
        )

    def get_threat_points(self):
        """Analyzes recent attacks to get high-level geographic data."""
        try:
            attacks = db.get_attacks(limit=100)
            points = []
            
            for attack in attacks:
                ip = attack.get('source_ip')
                if not ip or self.is_local_or_private(ip):
                    continue
                
                geo = self._get_geo_info(ip)
                if geo:
                    points.append({
                        "id": attack.get('id'),
                        "type": attack.get('attack_type') or attack.get('type', 'attack'),
                        "severity": attack.get('severity', 'medium'),
                        "lat": geo.get('lat'),
                        "lon": geo.get('lon'),
                        "city": geo.get('city'),
                        "country": geo.get('country'),
                        "timestamp": attack.get('created_at')
                    })
            
            return points
            
        except Exception as e:
            logger.error(f"Error generating threat map points: {e}")
            return []

    def _get_geo_info(self, ip):
        """Real GeoIP lookup with caching — no random/fake data."""
        if not ip or self.is_local_or_private(ip):
            return None
        if ip in self.geo_cache:
            return self.geo_cache[ip]
            
        try:
            import urllib.request
            import urllib.parse
            import json as _json
            
            clean_ip = urllib.parse.quote(str(ip).strip())
            req = urllib.request.Request(
                f"http://ip-api.com/json/{clean_ip}?fields=status,country,city,lat,lon",
                headers={"User-Agent": "HorusShield/2.0"}
            )
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = _json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                geo = {
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "city": data.get("city", "Unknown City"),
                    "country": data.get("country", "Unknown Country")
                }
                self.geo_cache[ip] = geo
                return geo
        except Exception as e:
            logger.debug(f"Geo lookup failed for {ip}: {e}")
        return None

threat_map_service = ThreatMapService()


