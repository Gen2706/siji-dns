#!/usr/bin/env python3
"""siji-DNS DoH/DoT/DoQ API"""
from flask import Blueprint, request, jsonify
from core.database import get_conn
from core.transport_manager import generate_dnsdist_config, reload_dnsdist, generate_self_signed_cert, get_dnsdist_status
from api.auth import require_auth, require_admin

doh_dot_bp = Blueprint('doh_dot', __name__)

@doh_dot_bp.route('/status', methods=['GET'])
@require_auth
def transport_status():
    with get_conn() as conn:
        settings = {r['key']: r['value'] for r in conn.execute(
            "SELECT key,value FROM settings WHERE category='transport'"
        ).fetchall()}
    status = get_dnsdist_status()
    status['settings'] = settings
    return jsonify(status)

@doh_dot_bp.route('/apply', methods=['POST'])
@require_admin
def apply_transport():
    with get_conn() as conn:
        settings = {r['key']: r['value'] for r in conn.execute("SELECT key,value FROM settings").fetchall()}
    generate_dnsdist_config(settings)
    ok, msg = reload_dnsdist()
    return jsonify({'success': ok, 'message': msg})

@doh_dot_bp.route('/generate-cert', methods=['POST'])
@require_admin
def gen_cert():
    d = request.json or {}
    domain = d.get('domain', 'siji-dns.local')
    cert, key = generate_self_signed_cert(domain)
    with get_conn() as conn:
        conn.execute("UPDATE settings SET value=? WHERE key='tls_cert'", (cert,))
        conn.execute("UPDATE settings SET value=? WHERE key='tls_key'", (key,))
    return jsonify({'cert': cert, 'key': key, 'message': 'Self-signed cert generated'})


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


#!/usr/bin/env python3
"""siji-DNS Stats API"""
from flask import Blueprint, request, jsonify
from core.database import get_conn
from api.auth import require_auth

stats_bp = Blueprint('stats', __name__)

@stats_bp.route('/overview', methods=['GET'])
@require_auth
def overview():
    with get_conn() as conn:
        zones_count = conn.execute("SELECT COUNT(*) FROM zones WHERE active=1").fetchone()[0]
        records_count = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        blocked_count = conn.execute("SELECT COUNT(*) FROM blocked_domains").fetchone()[0]
        bl_count = conn.execute("SELECT COUNT(*) FROM blocklists WHERE enabled=1").fetchone()[0]

        q_today = conn.execute("""
            SELECT COUNT(*) FROM query_log
            WHERE timestamp > datetime('now', 'start of day')
        """).fetchone()[0]

        q_blocked_today = conn.execute("""
            SELECT COUNT(*) FROM query_log
            WHERE timestamp > datetime('now', 'start of day') AND blocked=1
        """).fetchone()[0]

        q_last_hour = conn.execute("""
            SELECT COUNT(*) FROM query_log
            WHERE timestamp > datetime('now', '-1 hour')
        """).fetchone()[0]

    return jsonify({
        'zones': zones_count,
        'records': records_count,
        'blocked_domains': blocked_count,
        'active_blocklists': bl_count,
        'queries_today': q_today,
        'blocked_today': q_blocked_today,
        'queries_last_hour': q_last_hour,
    })

@stats_bp.route('/query-log', methods=['GET'])
@require_auth
def query_log():
    page  = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = (page - 1) * limit
    filter_blocked = request.args.get('blocked')
    filter_type    = request.args.get('type')
    search         = request.args.get('search', '')

    where_clauses = []
    params = []
    if filter_blocked == '1':
        where_clauses.append('blocked=1')
    if filter_type:
        where_clauses.append('query_type=?')
        params.append(filter_type.upper())
    if search:
        where_clauses.append('query_name LIKE ?')
        params.append(f'%{search}%')

    where = ('WHERE ' + ' AND '.join(where_clauses)) if where_clauses else ''

    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM query_log {where}", params).fetchone()[0]
        rows = [dict(r) for r in conn.execute(
            f"SELECT * FROM query_log {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()]

    return jsonify({'total': total, 'page': page, 'limit': limit, 'rows': rows})

@stats_bp.route('/top-domains', methods=['GET'])
@require_auth
def top_domains():
    hours = int(request.args.get('hours', 24))
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("""
            SELECT query_name, query_type, COUNT(*) as count,
                   SUM(blocked) as blocked_count
            FROM query_log
            WHERE timestamp > datetime('now', ?)
            GROUP BY query_name, query_type
            ORDER BY count DESC LIMIT 50
        """, (f"-{hours} hours",)).fetchall()]
    return jsonify(rows)

@stats_bp.route('/timeline', methods=['GET'])
@require_auth
def timeline():
    hours = int(request.args.get('hours', 24))
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("""
            SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                   COUNT(*) as total,
                   SUM(blocked) as blocked
            FROM query_log
            WHERE timestamp > datetime('now', ?)
            GROUP BY hour ORDER BY hour
        """, (f"-{hours} hours",)).fetchall()]
    return jsonify(rows)

@stats_bp.route('/audit-log', methods=['GET'])
@require_auth
def audit_log():
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 200"
        ).fetchall()]
    return jsonify(rows)
