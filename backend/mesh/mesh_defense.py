"""
HorusShield Mesh Defense — Feature 20
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Network topology analysis and isolation strategies using NetworkX.
"""

import networkx as nx
import json
import threading
import time

from database.db_manager import db
from utils.logger import get_logger
from config import active_config as config

logger = get_logger("mesh_defense", "mesh")

class MeshDefense:
    """Graph-based network defense engine.
    
    Models the network as a graph to identify critical nodes,
    detect single points of failure, and coordinate segment isolation.
    """
    
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.graph = nx.Graph()
        self._running = False
        self._update_thread = None
        self._lock = threading.Lock()

    def start(self):
        if self._running: return
        self._running = True
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self._update_thread.start()
        logger.info("Mesh Defense engine started.")

    def stop(self):
        self._running = False

    def _update_loop(self):
        """Periodic graph analysis."""
        while self._running:
            self.rebuild_topology()
            self._analyze_criticality()
            time.sleep(config.MESH_UPDATE_INTERVAL)

    def rebuild_topology(self):
        """Synchronize the NetworkX graph with the current database state."""
        with self._lock:
            self.graph.clear()
            
            # Add nodes (Devices)
            devices = db.get_all_devices()
            gateway_node = None
            
            for dev in devices:
                node_id = dev['mac_address']
                self.graph.add_node(node_id, 
                                  ip=dev.get('ip_address') or dev.get('ip') or 'Unknown', 
                                  type=dev.get('device_type') or 'node',
                                  status=dev.get('status') or 'active')
                if dev.get('is_gateway') or dev.get('device_type') == 'router':
                    gateway_node = node_id
            
            # Fallback to first device as hub if no explicit gateway
            if not gateway_node and devices:
                gateway_node = devices[0]['mac_address']
            
            # Add edges
            if gateway_node:
                for node in self.graph.nodes():
                    if node != gateway_node:
                        self.graph.add_edge(node, gateway_node)

            self._sync_topology_to_db()
            if self.socketio:
                self.socketio.emit('mesh_update', self.get_topology_data())

    def _sync_topology_to_db(self):
        """Persist the in-memory topology so REST routes can serve live data."""
        with db.get_connection() as conn:
            conn.execute("DELETE FROM mesh_edges")
            conn.execute("DELETE FROM mesh_nodes")

            for node_id, attr in self.graph.nodes(data=True):
                connections = [neighbor for neighbor in self.graph.neighbors(node_id)]
                conn.execute("""
                    INSERT INTO mesh_nodes (node_id, ip_address, mac_address, role, status, connections, centrality)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    node_id,
                    attr.get('ip'),
                    node_id,
                    attr.get('type', 'node'),
                    attr.get('status', 'active'),
                    json.dumps(connections),
                    0.0,
                ))

            for source_node, target_node in self.graph.edges():
                conn.execute("""
                    INSERT INTO mesh_edges (source_node, target_node, weight, status)
                    VALUES (?, ?, ?, ?)
                """, (source_node, target_node, 1.0, 'active'))

    def _analyze_criticality(self):
        """Identify critical nodes using centrality metrics."""
        if len(self.graph.nodes()) < 3: return
        
        # Betweenness Centrality
        try:
            centrality = nx.betweenness_centrality(self.graph)
            
            for node, value in centrality.items():
                if value > config.MESH_CRITICAL_THRESHOLD:
                    self._handle_critical_node(node, value)
                
                # Update DB
                db.update_mesh_node_status(node_id=node, status=self.graph.nodes[node].get('status', 'active'))
                # Special update for centrality
                with db.get_connection() as conn:
                    conn.execute("UPDATE mesh_nodes SET centrality=? WHERE node_id=?", (value, node))
                    
        except Exception as e:
            logger.error(f"Mesh analysis error: {e}")

    def _handle_critical_node(self, node_id, value):
        """Flags and alerts about a central node that is a potential bottleneck/target."""
        node_data = self.graph.nodes[node_id]
        ip = node_data.get('ip', 'Unknown')
        
        logger.warning(f"Critical Node Identified: {node_id} ({ip}) Centrality: {value:.2f}")
        
        db.add_alert(
            alert_type="mesh",
            title="🕸️ Mesh: Critical Node Identified",
            message=f"Node {ip} identified as a vital communication hub. Protecting this node is critical for network stability.",
            severity="medium",
            source="mesh_defense"
        )

    def get_topology_data(self):
        """Returns JSON-serializable graph for frontend visualization."""
        with self._lock:
            data = {
                "nodes": [],
                "links": []
            }
            for node, attr in self.graph.nodes(data=True):
                data["nodes"].append({
                    "id": node,
                    "ip": attr.get('ip'),
                    "type": attr.get('type'),
                    "status": attr.get('status')
                })
            for u, v in self.graph.edges():
                data["links"].append({"source": u, "target": v})
            return data

    def isolate_node(self, node_id):
        """Strategically isolates a node by blocking its edges in the mesh."""
        logger.critical(f"MESH ISOLATION: Severing connection for {node_id}")
        db.isolate_mesh_node(node_id)
        if self.socketio:
            self.socketio.emit('mesh_update', self.get_topology_data())
        return True
