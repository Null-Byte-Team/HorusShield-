"""
HorusShield Network Map Service — Feature 11
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Generating real-time network topology and traffic mapping data.
"""

from database.db_manager import db
from utils.logger import get_logger

logger = get_logger("network_map", "services")

class NetworkMapService:
    """Service to generate data for the 3D/2D network map.
    
    Combines device information with connection data to build
    a comprehensive map of the local ecosystem.
    """
    
    def __init__(self, socketio=None):
        self.socketio = socketio

    def get_map_data(self):
        """Builds a nodes-and-links representation of the network."""
        try:
            devices = db.get_all_devices()
            nodes = []
            links = []
            
            gateway_id = None
            
            # 1. Create Nodes
            for dev in devices:
                is_gateway = dev.get('is_gateway', 0) == 1
                node = {
                    "id": str(dev['id']),
                    "mac": dev['mac_address'],
                    "ip": dev['ip_address'],
                    "label": dev['hostname'] or dev['ip_address'],
                    "type": dev['device_type'],
                    "status": dev['status'],
                    "is_gateway": is_gateway,
                    "risk_score": dev.get('risk_score', 0)
                }
                nodes.append(node)
                if is_gateway:
                    gateway_id = str(dev['id'])
            
            # 2. Create Links
            # Simple logic: all devices connect to the gateway unless more data is available
            if gateway_id:
                for node in nodes:
                    if node['id'] != gateway_id:
                        links.append({
                            "source": node['id'],
                            "target": gateway_id,
                            "value": 1,
                            "status": node['status']
                        })
            
            return {"nodes": nodes, "links": links}
            
        except Exception as e:
            logger.error(f"Error generating network map data: {e}")
            return {"nodes": [], "links": []}

    def broadcast_update(self):
        """Emit the current map state to all connected clients."""
        if self.socketio:
            data = self.get_map_data()
            self.socketio.emit('network_map_update', data)
