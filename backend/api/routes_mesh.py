"""HorusShield Mesh API — Fixed"""
from flask import Blueprint, jsonify
from database.db_manager import db
from utils.logger import get_logger
from auth.decorators import login_required

mesh_bp = Blueprint('mesh', __name__)
logger = get_logger("routes_mesh", "api")


@mesh_bp.route('/topology', methods=['GET'])
@login_required
def get_topology():
    try:
        topo = db.get_mesh_topology()
        nodes = topo.get("nodes", [])
        links = topo.get("links", []) or topo.get("edges", [])

        # If mesh_nodes is empty, auto-sync from devices if available
        if not nodes:
            devices = db.get_all_devices()
            if devices:
                from flask import current_app
                mesh_engine = current_app.extensions.get('mesh')
                if mesh_engine:
                    mesh_engine.rebuild_topology()
                    topo = db.get_mesh_topology()
                    nodes = topo.get("nodes", [])
                    links = topo.get("links", []) or topo.get("edges", [])

        # Normalize node fields
        norm_nodes = []
        for n in nodes:
            node_id = n.get("id") or n.get("node_id") or n.get("mac_address") or n.get("ip_address","?")
            norm_nodes.append({
                **n,
                "id": node_id,
                "node_id": node_id,
                "ip": n.get("ip") or n.get("ip_address",""),
                "type": n.get("type") or n.get("role","node"),
                "status": n.get("status","active"),
            })
        norm_links = []
        for l in links:
            norm_links.append({
                **l,
                "source": l.get("source") or l.get("source_node",""),
                "target": l.get("target") or l.get("target_node",""),
            })
        return jsonify({"nodes": norm_nodes, "links": norm_links})
    except Exception as e:
        logger.error(f"get_topology: {e}")
        return jsonify({"nodes": [], "links": []}), 200


@mesh_bp.route('/nodes/critical', methods=['GET'])
@login_required
def get_critical_nodes():
    try:
        with db.get_connection() as conn:
            # Check if column exists first
            cols = [r[1] for r in conn.execute("PRAGMA table_info(mesh_nodes)").fetchall()]
            if "centrality" in cols:
                rows = conn.execute(
                    "SELECT * FROM mesh_nodes WHERE centrality > 0.5 ORDER BY centrality DESC"
                ).fetchall()
                return jsonify([dict(r) for r in rows])
            else:
                rows = conn.execute("SELECT * FROM mesh_nodes LIMIT 10").fetchall()
                return jsonify([dict(r) for r in rows])
    except Exception as e:
        logger.error(f"get_critical_nodes: {e}")
        return jsonify([]), 200
