#!/usr/bin/env python3
"""siji-DNS Settings API"""
from flask import Blueprint, request, jsonify
from core.database import get_conn
from core.bind_manager import write_named_options, _reload_bind
from api.auth import require_auth, require_admin

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/', methods=['GET'])
@require_auth
def get_settings():
    with get_conn() as conn:
        rows = conn.execute("SELECT key, value, category FROM settings ORDER BY category, key").fetchall()
        result = {}
        for r in rows:
            result[r['key']] = {'value': r['value'], 'category': r['category']}
    return jsonify(result)

@settings_bp.route('/', methods=['PUT'])
@require_admin
def update_settings():
    updates = request.json or {}
    with get_conn() as conn:
        for key, value in updates.items():
            conn.execute("""
                INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """, (key, str(value)))
        settings = {r['key']: r['value'] for r in conn.execute("SELECT key,value FROM settings").fetchall()}
        forwarders = [dict(r) for r in conn.execute(
            "SELECT * FROM forwarders WHERE enabled=1 ORDER BY priority").fetchall()]
        write_named_options(settings, forwarders)
        _reload_bind()
    return jsonify({'message': 'Settings saved and applied'})
