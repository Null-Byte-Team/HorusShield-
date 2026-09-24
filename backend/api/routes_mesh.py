"""HorusShield Mesh API — Enhanced"""
from flask import Blueprint, jsonify, current_app
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

        # If mesh_nodes is empty, auto-sync/rebuild immediately
        if not nodes:
            mesh_engine = current_app.extensions.get('mesh') if current_app else None
            if mesh_engine:
                mesh_engine.rebuild_topology()
            else:
                from mesh.mesh_defense import MeshDefense
                MeshDefense().rebuild_topology()
            topo = db.get_mesh_topology()
            nodes = topo.get("nodes", [])
            links = topo.get("links", []) or topo.get("edges", [])

        # Normalize node fields
        norm_nodes = []
        for n in nodes:
            node_id = n.get("id") or n.get("node_id") or n.get("mac_address") or n.get("ip_address", "?")
            norm_nodes.append({
                **n,
                "id": node_id,
                "node_id": node_id,
                "ip": n.get("ip") or n.get("ip_address", ""),
                "type": n.get("type") or n.get("role", "node"),
                "role": n.get("role") or n.get("type", "node"),
                "status": n.get("status", "active"),
                "centrality": float(n.get("centrality") or 0.8),
            })
        norm_links = []
        for l in links:
            norm_links.append({
                **l,
                "source": l.get("source") or l.get("source_node", ""),
                "target": l.get("target") or l.get("target_node", ""),
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
            # Check if mesh_nodes has rows, if not rebuild
            cnt = conn.execute("SELECT COUNT(*) FROM mesh_nodes").fetchone()[0]
            if cnt == 0:
                mesh_engine = current_app.extensions.get('mesh') if current_app else None
                if mesh_engine:
                    mesh_engine.rebuild_topology()
                else:
                    from mesh.mesh_defense import MeshDefense
                    MeshDefense().rebuild_topology()

            cols = [r[1] for r in conn.execute("PRAGMA table_info(mesh_nodes)").fetchall()]
            if "centrality" in cols:
                rows = conn.execute(
                    """SELECT * FROM mesh_nodes 
                       ORDER BY centrality DESC, 
                                CASE WHEN role IN ('gateway','router') THEN 0 ELSE 1 END,
                                id ASC 
                       LIMIT 10"""
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM mesh_nodes LIMIT 10").fetchall()
            
            res = []
            for r in rows:
                d = dict(r)
                if not d.get("centrality"):
                    d["centrality"] = 0.95 if d.get("role") in ("gateway", "router") else 0.80
                res.append(d)
            return jsonify(res)
    except Exception as e:
        logger.error(f"get_critical_nodes: {e}")
        return jsonify([]), 200

