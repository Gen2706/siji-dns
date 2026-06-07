#!/usr/bin/env python3
"""siji-DNS Forwarding API"""
from flask import Blueprint, request, jsonify
from core.database import get_conn
from core.bind_manager import write_named_options, _reload_bind
from api.auth import require_auth, require_admin

forwarding_bp = Blueprint('forwarding', __name__)

@forwarding_bp.route('/', methods=['GET'])
@require_auth
def list_forwarders():
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM forwarders ORDER BY priority").fetchall()]
    return jsonify(rows)

@forwarding_bp.route('/', methods=['POST'])
@require_admin
def add_forwarder():
    d = request.json or {}
    if not d.get('ip'):
        return jsonify({'error': 'IP required'}), 400
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO forwarders (name, ip, port, protocol, priority, enabled)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (d.get('name', d['ip']), d['ip'], d.get('port', 53),
              d.get('protocol', 'udp'), d.get('priority', 10), 1))
        _rebuild_forwarders(conn)
    return jsonify({'message': 'Forwarder added'}), 201

@forwarding_bp.route('/<int:fwd_id>', methods=['DELETE'])
@require_admin
def delete_forwarder(fwd_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM forwarders WHERE id=?", (fwd_id,))
        _rebuild_forwarders(conn)
    return jsonify({'message': 'Forwarder deleted'})

@forwarding_bp.route('/<int:fwd_id>/toggle', methods=['POST'])
@require_admin
def toggle_forwarder(fwd_id):
    with get_conn() as conn:
        conn.execute("UPDATE forwarders SET enabled = NOT enabled WHERE id=?", (fwd_id,))
        _rebuild_forwarders(conn)
    return jsonify({'message': 'Toggled'})

def _rebuild_forwarders(conn):
    settings = {r['key']: r['value'] for r in conn.execute("SELECT key, value FROM settings").fetchall()}
    forwarders = [dict(r) for r in conn.execute(
        "SELECT * FROM forwarders WHERE enabled=1 ORDER BY priority").fetchall()]
    write_named_options(settings, forwarders)
    _reload_bind()
