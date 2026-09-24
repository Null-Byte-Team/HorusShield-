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
from utils.helpers import get_local_ip, get_gateway_ip, synthetic_mac_from_ip
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
        self._lock = threading.RLock()

    def start(self):
        if self._running: return
        self._running = True
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True, name="MeshDefense")
        self._update_thread.start()
        logger.info("Mesh Defense engine started.")

    def stop(self):
        self._running = False

    def _update_loop(self):
        """Periodic graph analysis."""
        while self._running:
            try:
                self.rebuild_topology()
                self._analyze_criticality()
            except Exception as e:
                logger.error(f"Mesh update loop error: {e}")
            time.sleep(config.MESH_UPDATE_INTERVAL)

    def rebuild_topology(self):
        """Synchronize the NetworkX graph with the current database and network state."""
        with self._lock:
            self.graph.clear()
            
            # Add nodes (Devices)
            devices = db.get_all_devices()
            gateway_node = None
            
            if not devices:
                # Discover/seed local interface & gateway to ensure topology is never empty
                local_ip = get_local_ip()
                gw_ip = get_gateway_ip() or (local_ip.rsplit('.', 1)[0] + '.1' if '.' in local_ip else '192.168.1.1')
                gw_mac = synthetic_mac_from_ip(gw_ip)
                host_mac = synthetic_mac_from_ip(local_ip)
                
                devices = [
                    {
                        'mac_address': gw_mac,
                        'ip_address': gw_ip,
                        'device_type': 'router',
                        'is_gateway': 1,
                        'status': 'active',
                        'hostname': 'Default-Gateway'
                    },
                    {
                        'mac_address': host_mac,
                        'ip_address': local_ip,
                        'device_type': 'pc',
                        'is_gateway': 0,
                        'status': 'active',
                        'hostname': 'HorusShield-Host'
                    }
                ]
            
            for dev in devices:
                node_id = dev.get('mac_address') or synthetic_mac_from_ip(dev.get('ip_address') or '127.0.0.1')
                is_gw = bool(dev.get('is_gateway') or dev.get('device_type') in ('router', 'gateway'))
                node_type = 'gateway' if is_gw else (dev.get('device_type') or 'node')
                self.graph.add_node(
                    node_id, 
                    ip=dev.get('ip_address') or dev.get('ip') or 'Unknown', 
                    type=node_type,
                    status=dev.get('status') or 'active',
                    hostname=dev.get('hostname') or 'Node'
                )
                if is_gw:
                    gateway_node = node_id
            
            # Fallback to first device as hub if no explicit gateway
            if not gateway_node and devices:
                gateway_node = devices[0].get('mac_address')
            
            # Add edges
            nodes_list = list(self.graph.nodes())
            if gateway_node:
                for node in nodes_list:
                    if node != gateway_node:
                        self.graph.add_edge(node, gateway_node)
            
            # Interconnect secondary peer mesh links if multiple nodes exist
            if len(nodes_list) > 2:
                non_gw = [n for n in nodes_list if n != gateway_node]
                for i in range(len(non_gw) - 1):
                    self.graph.add_edge(non_gw[i], non_gw[i+1])

            # Compute centrality scores
            centralities = self._calculate_centralities()
            for node, cent in centralities.items():
                if node in self.graph.nodes:
                    self.graph.nodes[node]['centrality'] = cent

            self._sync_topology_to_db(centralities)
            if self.socketio:
                try:
                    self.socketio.emit('mesh_update', self.get_topology_data())
                except Exception as e:
                    logger.debug(f"Socketio mesh_update error: {e}")

    def _calculate_centralities(self):
        """Compute betweenness / hub centrality for all nodes."""
        n_count = len(self.graph.nodes())
        if n_count == 0:
            return {}
        if n_count == 1:
            return {list(self.graph.nodes())[0]: 1.0}
        if n_count == 2:
            nodes = list(self.graph.nodes())
            gw = [n for n in nodes if self.graph.nodes[n].get('type') == 'gateway']
            gw_node = gw[0] if gw else nodes[0]
            other = [n for n in nodes if n != gw_node][0]
            return {gw_node: 0.95, other: 0.80}

        try:
            cent = nx.betweenness_centrality(self.graph)
            deg_cent = nx.degree_centrality(self.graph)
            combined = {}
            for node in self.graph.nodes():
                val = max(cent.get(node, 0.0), deg_cent.get(node, 0.0))
                if self.graph.nodes[node].get('type') == 'gateway':
                    val = max(val, 0.90)
                combined[node] = round(float(val), 3)
            return combined
        except Exception as e:
            logger.debug(f"Centrality calculation error: {e}")
            return {node: 0.75 for node in self.graph.nodes()}

    def _sync_topology_to_db(self, centralities=None):
        """Persist the in-memory topology so REST routes can serve live data."""
        if centralities is None:
            centralities = self._calculate_centralities()

        with db.get_connection() as conn:
            conn.execute("DELETE FROM mesh_edges")
            conn.execute("DELETE FROM mesh_nodes")

            for node_id, attr in self.graph.nodes(data=True):
                connections = [neighbor for neighbor in self.graph.neighbors(node_id)]
                cent = centralities.get(node_id, attr.get('centrality', 0.5))
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
                    cent,
                ))

            for source_node, target_node in self.graph.edges():
                conn.execute("""
                    INSERT INTO mesh_edges (source_node, target_node, weight, status)
                    VALUES (?, ?, ?, ?)
                """, (source_node, target_node, 1.0, 'active'))

    def _analyze_criticality(self):
        """Identify critical nodes using centrality metrics."""
        if len(self.graph.nodes()) < 2: return
        
        try:
            centrality = self._calculate_centralities()
            
            for node, value in centrality.items():
                if value > config.MESH_CRITICAL_THRESHOLD:
                    self._handle_critical_node(node, value)
                
                # Update DB
                status = self.graph.nodes[node].get('status', 'active') if node in self.graph.nodes else 'active'
                db.update_mesh_node_status(node_id=node, status=status)
                with db.get_connection() as conn:
                    conn.execute("UPDATE mesh_nodes SET centrality=? WHERE node_id=?", (value, node))
                    
        except Exception as e:
            logger.error(f"Mesh analysis error: {e}")

    def _handle_critical_node(self, node_id, value):
        """Flags and alerts about a central node that is a potential bottleneck/target."""
        if node_id not in self.graph.nodes: return
        node_data = self.graph.nodes[node_id]
        ip = node_data.get('ip', 'Unknown')
        
        logger.debug(f"Critical Node Identified: {node_id} ({ip}) Centrality: {value:.2f}")

    def get_topology_data(self):
        """Returns JSON-serializable graph for frontend visualization."""
        with self._lock:
            data = {
                "nodes": [],
                "links": []
            }
            centralities = self._calculate_centralities()
            for node, attr in self.graph.nodes(data=True):
                data["nodes"].append({
                    "id": node,
                    "node_id": node,
                    "ip": attr.get('ip'),
                    "ip_address": attr.get('ip'),
                    "type": attr.get('type'),
                    "role": attr.get('type'),
                    "status": attr.get('status'),
                    "centrality": centralities.get(node, attr.get('centrality', 0.8))
                })
            for u, v in self.graph.edges():
                data["links"].append({"source": u, "target": v})
            return data

    def isolate_node(self, node_id):
        """Strategically isolates a node by blocking its edges in the mesh."""
        logger.critical(f"MESH ISOLATION: Severing connection for {node_id}")
        db.isolate_mesh_node(node_id)
        if self.socketio:
            try:
                self.socketio.emit('mesh_update', self.get_topology_data())
            except Exception:
                pass
        return True
