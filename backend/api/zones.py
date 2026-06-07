#!/usr/bin/env python3
"""siji-DNS Zones API"""

from flask import Blueprint, request, jsonify
from core.database import get_conn
from core.bind_manager import write_zone_file, write_named_local, _reload_bind, get_bind_status
from api.auth import require_auth, require_admin

zones_bp = Blueprint('zones', __name__)

@zones_bp.route('/', methods=['GET'])
@require_auth
def list_zones():
    with get_conn() as conn:
        zones = [dict(r) for r in conn.execute(
            "SELECT * FROM zones ORDER BY name"
        ).fetchall()]
    return jsonify(zones)

@zones_bp.route('/', methods=['POST'])
@require_admin
def create_zone():
    d = request.json or {}
    required = ['name']
    if not all(k in d for k in required):
        return jsonify({'error': 'Missing required fields'}), 400

    name = d['name'].lower().rstrip('.')
    with get_conn() as conn:
        existing = conn.execute("SELECT id FROM zones WHERE name=?", (name,)).fetchone()
        if existing:
            return jsonify({'error': 'Zone already exists'}), 409

        conn.execute("""
            INSERT INTO zones (name, type, ttl, refresh, retry, expire, minimum, ns, email)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            name,
            d.get('type', 'master'),
            d.get('ttl', 3600),
            d.get('refresh', 86400),
            d.get('retry', 7200),
            d.get('expire', 604800),
            d.get('minimum', 300),
            d.get('ns', f"ns1.{name}"),
            d.get('email', f"hostmaster.{name}"),
        ))
        zone = dict(conn.execute("SELECT * FROM zones WHERE name=?", (name,)).fetchone())

        # Auto-create NS and SOA records
        conn.execute("""
            INSERT INTO records (zone_id, name, type, value, ttl)
            VALUES (?, '@', 'NS', ?, 3600)
        """, (zone['id'], d.get('ns', f"ns1.{name}.")))

        # Write zone file
        records = [dict(r) for r in conn.execute(
            "SELECT * FROM records WHERE zone_id=?", (zone['id'],)
        ).fetchall()]
        write_zone_file(zone, records)

        # Update named.conf.local
        all_zones = [dict(r) for r in conn.execute("SELECT * FROM zones WHERE active=1").fetchall()]
        write_named_local(all_zones)
        _reload_bind()

        _audit(conn, request, 'create_zone', name)

    return jsonify(zone), 201


@zones_bp.route('/<int:zone_id>', methods=['GET'])
@require_auth
def get_zone(zone_id):
    with get_conn() as conn:
        zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
        if not zone:
            return jsonify({'error': 'Zone not found'}), 404
        return jsonify(dict(zone))


@zones_bp.route('/<int:zone_id>', methods=['PUT'])
@require_admin
def update_zone(zone_id):
    d = request.json or {}
    with get_conn() as conn:
        zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
        if not zone:
            return jsonify({'error': 'Zone not found'}), 404

        conn.execute("""
            UPDATE zones SET ttl=?, refresh=?, retry=?, expire=?, minimum=?,
                            ns=?, email=?, updated_at=datetime('now')
            WHERE id=?
        """, (
            d.get('ttl', zone['ttl']),
            d.get('refresh', zone['refresh']),
            d.get('retry', zone['retry']),
            d.get('expire', zone['expire']),
            d.get('minimum', zone['minimum']),
            d.get('ns', zone['ns']),
            d.get('email', zone['email']),
            zone_id
        ))

        zone = dict(conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone())
        records = [dict(r) for r in conn.execute(
            "SELECT * FROM records WHERE zone_id=?", (zone_id,)
        ).fetchall()]
        write_zone_file(zone, records)
        _reload_bind()
        _audit(conn, request, 'update_zone', zone['name'])

    return jsonify(zone)


@zones_bp.route('/<int:zone_id>', methods=['DELETE'])
@require_admin
def delete_zone(zone_id):
    with get_conn() as conn:
        zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
        if not zone:
            return jsonify({'error': 'Zone not found'}), 404
        zone_name = zone['name']
        conn.execute("DELETE FROM zones WHERE id=?", (zone_id,))
        all_zones = [dict(r) for r in conn.execute(
            "SELECT * FROM zones WHERE active=1"
        ).fetchall()]
        write_named_local(all_zones)
        _reload_bind()
        _audit(conn, request, 'delete_zone', zone_name)

    # Remove zone file
    import os
    zone_file = f"/etc/bind/zones/db.{zone_name}"
    if os.path.exists(zone_file):
        os.remove(zone_file)

    return jsonify({'message': f'Zone {zone_name} deleted'})


@zones_bp.route('/status', methods=['GET'])
@require_auth
def bind_status():
    return jsonify(get_bind_status())


def _audit(conn, req, action, target):
    token = req.headers.get('Authorization', '').replace('Bearer ', '')
    user = 'unknown'
    try:
        from api.auth import verify_token
        from flask import current_app
        p = verify_token(token, current_app.config['SECRET_KEY'])
        if p: user = p['u']
    except Exception:
        pass
    conn.execute(
        "INSERT INTO audit_log (user, action, target, ip) VALUES (?, ?, ?, ?)",
        (user, action, target, req.remote_addr)
    )
