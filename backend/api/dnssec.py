#!/usr/bin/env python3
"""siji-DNS DNSSEC API"""
from flask import Blueprint, request, jsonify
from core.database import get_conn
from core.dnssec_manager import generate_ksk, generate_zsk, sign_zone, get_ds_records, validate_dnssec, get_dnssec_status
from api.auth import require_auth, require_admin

dnssec_bp = Blueprint('dnssec', __name__)

@dnssec_bp.route('/status', methods=['GET'])
@require_auth
def dnssec_status():
    return jsonify(get_dnssec_status())

@dnssec_bp.route('/keys/<int:zone_id>', methods=['GET'])
@require_auth
def list_keys(zone_id):
    with get_conn() as conn:
        keys = [dict(r) for r in conn.execute(
            "SELECT id,zone_id,key_type,algorithm,key_tag,activated,expires,created_at FROM dnssec_keys WHERE zone_id=?",
            (zone_id,)).fetchall()]
    return jsonify(keys)

@dnssec_bp.route('/generate/<int:zone_id>', methods=['POST'])
@require_admin
def generate_keys(zone_id):
    with get_conn() as conn:
        zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
        if not zone:
            return jsonify({'error': 'Zone not found'}), 404
        ksk = generate_ksk(zone['name'])
        zsk = generate_zsk(zone['name'])
        for key in [ksk, zsk]:
            conn.execute("""
                INSERT INTO dnssec_keys (zone_id, key_type, algorithm, key_tag, public_key)
                VALUES (?, ?, ?, ?, ?)
            """, (zone_id, key['key_type'], key['algorithm'], key['key_tag'], key['public_key']))
        conn.execute("UPDATE zones SET dnssec=1 WHERE id=?", (zone_id,))
    return jsonify({'ksk': ksk['key_tag'], 'zsk': zsk['key_tag'], 'message': 'Keys generated'})

@dnssec_bp.route('/sign/<int:zone_id>', methods=['POST'])
@require_admin
def sign_zone_api(zone_id):
    with get_conn() as conn:
        zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
        if not zone:
            return jsonify({'error': 'Zone not found'}), 404
        zone_file = f"/etc/bind/zones/db.{zone['name']}"
        signed, output = sign_zone(zone['name'], zone_file)
    return jsonify({'signed_file': signed, 'message': 'Zone signed'})

@dnssec_bp.route('/ds/<int:zone_id>', methods=['GET'])
@require_auth
def get_ds(zone_id):
    with get_conn() as conn:
        zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
        if not zone:
            return jsonify({'error': 'Zone not found'}), 404
        ds = get_ds_records(zone['name'])
    return jsonify({'ds_records': ds, 'zone': zone['name']})

@dnssec_bp.route('/validate/<int:zone_id>', methods=['GET'])
@require_auth
def validate(zone_id):
    with get_conn() as conn:
        zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
        if not zone:
            return jsonify({'error': 'Zone not found'}), 404
    return jsonify(validate_dnssec(zone['name']))
