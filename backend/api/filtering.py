#!/usr/bin/env python3
"""siji-DNS Filtering API"""
from flask import Blueprint, request, jsonify
from core.database import get_conn
from core.filter_engine import rebuild_all_blocklists, check_domain_blocked, is_valid_domain
from api.auth import require_auth, require_admin
import threading

filtering_bp = Blueprint('filtering', __name__)

@filtering_bp.route('/blocklists', methods=['GET'])
@require_auth
def list_blocklists():
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM blocklists ORDER BY name").fetchall()]
    return jsonify(rows)

@filtering_bp.route('/blocklists', methods=['POST'])
@require_admin
def add_blocklist():
    d = request.json or {}
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO blocklists (name, source_type, source_url, entries, enabled)
            VALUES (?, ?, ?, ?, 1)
        """, (d.get('name','Custom'), d.get('source_type','url'),
              d.get('source_url'), d.get('entries')))
    return jsonify({'message': 'Blocklist added'}), 201

@filtering_bp.route('/blocklists/<int:bl_id>', methods=['DELETE'])
@require_admin
def delete_blocklist(bl_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM blocklists WHERE id=?", (bl_id,))
    return jsonify({'message': 'Deleted'})

@filtering_bp.route('/blocklists/<int:bl_id>/toggle', methods=['POST'])
@require_admin
def toggle_blocklist(bl_id):
    with get_conn() as conn:
        conn.execute("UPDATE blocklists SET enabled = NOT enabled WHERE id=?", (bl_id,))
    return jsonify({'message': 'Toggled'})

@filtering_bp.route('/refresh', methods=['POST'])
@require_admin
def refresh_blocklists():
    def _do_refresh():
        with get_conn() as conn:
            blocklists = [dict(r) for r in conn.execute("SELECT * FROM blocklists WHERE enabled=1").fetchall()]
            settings = {r['key']: r['value'] for r in conn.execute("SELECT key, value FROM settings").fetchall()}
        rebuild_all_blocklists(blocklists, settings)
    threading.Thread(target=_do_refresh, daemon=True).start()
    return jsonify({'message': 'Refresh started in background'})

@filtering_bp.route('/whitelist', methods=['GET'])
@require_auth
def list_whitelist():
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM whitelist ORDER BY domain").fetchall()]
    return jsonify(rows)

@filtering_bp.route('/whitelist', methods=['POST'])
@require_admin
def add_whitelist():
    d = request.json or {}
    domain = d.get('domain','').lower().strip()
    if not is_valid_domain(domain):
        return jsonify({'error': 'Invalid domain'}), 400
    with get_conn() as conn:
        conn.execute("INSERT OR IGNORE INTO whitelist (domain, reason) VALUES (?, ?)",
                    (domain, d.get('reason','')))
    return jsonify({'message': f'{domain} whitelisted'}), 201

@filtering_bp.route('/whitelist/<int:wl_id>', methods=['DELETE'])
@require_admin
def remove_whitelist(wl_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM whitelist WHERE id=?", (wl_id,))
    return jsonify({'message': 'Removed'})

@filtering_bp.route('/check/<domain>', methods=['GET'])
@require_auth
def check_domain(domain):
    with get_conn() as conn:
        blocked, reason = check_domain_blocked(domain, conn)
    return jsonify({'domain': domain, 'blocked': blocked, 'reason': reason})

@filtering_bp.route('/custom-domains', methods=['GET'])
@require_auth
def list_custom_blocked():
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM blocked_domains WHERE blocklist_id IS NULL ORDER BY domain"
        ).fetchall()]
    return jsonify(rows)

@filtering_bp.route('/custom-domains', methods=['POST'])
@require_admin
def add_custom_blocked():
    d = request.json or {}
    domain = d.get('domain','').lower().strip()
    if not is_valid_domain(domain):
        return jsonify({'error': 'Invalid domain'}), 400
    with get_conn() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO blocked_domains (domain, action, redirect_ip)
            VALUES (?, ?, ?)
        """, (domain, d.get('action','nxdomain'), d.get('redirect_ip')))
    return jsonify({'message': f'{domain} blocked'}), 201

@filtering_bp.route('/custom-domains/<int:domain_id>', methods=['DELETE'])
@require_admin
def remove_custom_blocked(domain_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM blocked_domains WHERE id=?", (domain_id,))
    return jsonify({'message': 'Unblocked'})
