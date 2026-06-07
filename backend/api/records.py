#!/usr/bin/env python3
"""siji-DNS Records API"""

from flask import Blueprint, request, jsonify
from core.database import get_conn
from core.bind_manager import write_zone_file, _reload_bind
from api.auth import require_auth, require_admin

records_bp = Blueprint('records', __name__)

VALID_TYPES = {'A','AAAA','CNAME','MX','NS','TXT','SRV','PTR','CAA','NAPTR','DNSKEY','DS','SOA'}

@records_bp.route('/<int:zone_id>', methods=['GET'])
@require_auth
def list_records(zone_id):
    with get_conn() as conn:
        records = [dict(r) for r in conn.execute(
            "SELECT * FROM records WHERE zone_id=? ORDER BY type, name",
            (zone_id,)
        ).fetchall()]
    return jsonify(records)

@records_bp.route('/<int:zone_id>', methods=['POST'])
@require_admin
def create_record(zone_id):
    d = request.json or {}
    rtype = d.get('type', '').upper()
    if rtype not in VALID_TYPES:
        return jsonify({'error': f'Invalid record type: {rtype}'}), 400
    if not d.get('name') or not d.get('value'):
        return jsonify({'error': 'name and value required'}), 400

    with get_conn() as conn:
        zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
        if not zone:
            return jsonify({'error': 'Zone not found'}), 404

        conn.execute("""
            INSERT INTO records (zone_id, name, type, value, ttl, priority)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (zone_id, d['name'], rtype, d['value'],
              d.get('ttl', zone['ttl']), d.get('priority', 0)))

        zone = dict(zone)
        records = [dict(r) for r in conn.execute(
            "SELECT * FROM records WHERE zone_id=?", (zone_id,)
        ).fetchall()]
        write_zone_file(zone, records)
        _reload_bind()

    return jsonify({'message': 'Record created'}), 201

@records_bp.route('/<int:zone_id>/<int:record_id>', methods=['PUT'])
@require_admin
def update_record(zone_id, record_id):
    d = request.json or {}
    with get_conn() as conn:
        rec = conn.execute("SELECT * FROM records WHERE id=? AND zone_id=?",
                           (record_id, zone_id)).fetchone()
        if not rec:
            return jsonify({'error': 'Record not found'}), 404
        conn.execute("""
            UPDATE records SET name=?, type=?, value=?, ttl=?, priority=?,
                              updated_at=datetime('now')
            WHERE id=?
        """, (d.get('name', rec['name']), d.get('type', rec['type']).upper(),
              d.get('value', rec['value']), d.get('ttl', rec['ttl']),
              d.get('priority', rec['priority']), record_id))

        zone = dict(conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone())
        records = [dict(r) for r in conn.execute(
            "SELECT * FROM records WHERE zone_id=?", (zone_id,)).fetchall()]
        write_zone_file(zone, records)
        _reload_bind()

    return jsonify({'message': 'Record updated'})

@records_bp.route('/<int:zone_id>/<int:record_id>', methods=['DELETE'])
@require_admin
def delete_record(zone_id, record_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM records WHERE id=? AND zone_id=?", (record_id, zone_id))
        zone = dict(conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone())
        records = [dict(r) for r in conn.execute(
            "SELECT * FROM records WHERE zone_id=?", (zone_id,)).fetchall()]
        write_zone_file(zone, records)
        _reload_bind()
    return jsonify({'message': 'Record deleted'})
