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
        # We'd use a local GeoLite2 DB in production, using ip-api.com for demo
        self.geo_cache = {}

    def get_threat_points(self):
        """Analyzes recent attacks to get high-level geographic data."""
        try:
            attacks = db.get_attacks(limit=100)
            points = []
            
            for attack in attacks:
                ip = attack.get('source_ip')
                if not ip or ip.startswith('192.168.') or ip.startswith('10.'):
                    continue
                
                geo = self._get_geo_info(ip)
                if geo:
                    points.append({
                        "id": attack['id'],
                        "type": attack['attack_type'],
                        "severity": attack['severity'],
                        "lat": geo.get('lat'),
                        "lon": geo.get('lon'),
                        "city": geo.get('city'),
                        "country": geo.get('country'),
                        "timestamp": attack['created_at']
                    })
            
            return points
            
        except Exception as e:
            logger.error(f"Error generating threat map points: {e}")
            return []

    def _get_geo_info(self, ip):
        """Mock/Real GeoIP lookup."""
        if ip in self.geo_cache:
            return self.geo_cache[ip]
            
        try:
            # Simple free API for demonstration
            # Note: rate limited, don't use in production loops
            # r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
            # data = r.json()
            
            # For Demo: Random Global Points
            data = {
                "lat": (random.random() * 120) - 60,
                "lon": (random.random() * 360) - 180,
                "city": "Unknown City",
                "country": "Unknown Country"
            }
            self.geo_cache[ip] = data
            return data
        except Exception as e:
            logger.debug(f"Geo lookup failed for {ip}: {e}")
            return None

