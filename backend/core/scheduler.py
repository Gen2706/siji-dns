#!/usr/bin/env python3
"""
siji-DNS Background Scheduler
Handles periodic tasks: blocklist refresh, stats collection, DNSSEC rotation
"""

import logging
import threading
import time
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
_scheduler_thread = None
_stop_event = threading.Event()


def init_scheduler(app, socketio):
    global _scheduler_thread
    _stop_event.clear()
    _scheduler_thread = threading.Thread(
        target=_run_scheduler,
        args=(app, socketio),
        daemon=True
    )
    _scheduler_thread.start()
    logger.info("siji-DNS scheduler started")


def _run_scheduler(app, socketio):
    last_blocklist_update = datetime.min
    last_stats_push       = datetime.min
    last_log_cleanup      = datetime.min

    while not _stop_event.is_set():
        now = datetime.utcnow()

        with app.app_context():
            from core.database import get_conn
            with get_conn() as conn:
                settings = {r['key']: r['value'] for r in
                            conn.execute("SELECT key, value FROM settings").fetchall()}

            # ── Stats push every 10s ─────────────────────────────────────
            if (now - last_stats_push).seconds >= 10:
                try:
                    stats = _collect_stats(settings)
                    socketio.emit('stats_update', stats)
                    last_stats_push = now
                except Exception as e:
                    logger.debug(f"Stats collection error: {e}")

            # ── Blocklist refresh every 24h ──────────────────────────────
            bl_interval = int(settings.get('blocklist_refresh_hours', 24))
            if (now - last_blocklist_update) > timedelta(hours=bl_interval):
                try:
                    _refresh_blocklists(settings)
                    last_blocklist_update = now
                    socketio.emit('notification', {
                        'type': 'success',
                        'message': 'Blocklists updated successfully'
                    })
                except Exception as e:
                    logger.error(f"Blocklist refresh error: {e}")
                    socketio.emit('notification', {
                        'type': 'error',
                        'message': f'Blocklist refresh failed: {e}'
                    })

            # ── Query log cleanup ────────────────────────────────────────
            if (now - last_log_cleanup).seconds >= 3600:
                try:
                    _cleanup_logs(settings)
                    last_log_cleanup = now
                except Exception as e:
                    logger.debug(f"Log cleanup error: {e}")

        _stop_event.wait(timeout=5)


def _collect_stats(settings):
    """Collect current DNS server stats"""
    import subprocess, re

    stats = {
        'timestamp': datetime.utcnow().isoformat(),
        'bind': {},
        'dnsdist': {},
        'queries': {},
    }

    # BIND stats via rndc
    try:
        r = subprocess.run("rndc stats && cat /var/cache/bind/named.stats",
                           shell=True, capture_output=True, text=True)
        if r.returncode == 0:
            # Parse key stats
            for line in r.stdout.split('\n'):
                if 'queries resulted in successful answer' in line:
                    m = re.search(r'(\d+)', line)
                    if m: stats['bind']['successful'] = int(m.group(1))
                elif 'queries resulted in NXDOMAIN' in line:
                    m = re.search(r'(\d+)', line)
                    if m: stats['bind']['nxdomain'] = int(m.group(1))
                elif 'recursive queries' in line:
                    m = re.search(r'(\d+)', line)
                    if m: stats['bind']['recursive'] = int(m.group(1))
    except Exception:
        pass

    # Query log stats from DB
    try:
        from core.database import get_conn
        with get_conn() as conn:
            row = conn.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(blocked) as blocked,
                    AVG(latency_ms) as avg_latency
                FROM query_log 
                WHERE timestamp > datetime('now', '-1 hour')
            """).fetchone()
            if row:
                stats['queries'] = {
                    'last_hour_total':   row['total'] or 0,
                    'last_hour_blocked': row['blocked'] or 0,
                    'avg_latency_ms':    round(row['avg_latency'] or 0, 2),
                }

            # Top queried domains
            top = conn.execute("""
                SELECT query_name, COUNT(*) as cnt
                FROM query_log
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY query_name ORDER BY cnt DESC LIMIT 10
            """).fetchall()
            stats['top_domains'] = [dict(r) for r in top]

            # Blocked stats
            blocked = conn.execute("""
                SELECT COUNT(*) as cnt FROM blocked_domains
            """).fetchone()
            stats['blocked_domains_total'] = blocked['cnt'] if blocked else 0
    except Exception as e:
        logger.debug(f"DB stats error: {e}")

    return stats


def _refresh_blocklists(settings):
    from core.database import get_conn
    from core.filter_engine import rebuild_all_blocklists

    with get_conn() as conn:
        blocklists = [dict(r) for r in
                      conn.execute("SELECT * FROM blocklists WHERE enabled=1").fetchall()]

    count, errors, ok, msg = rebuild_all_blocklists(blocklists, settings)
    if ok:
        from core.database import get_conn
        with get_conn() as conn:
            conn.execute("""
                UPDATE blocklists SET last_updated=datetime('now')
                WHERE enabled=1
            """)
    logger.info(f"Blocklist refresh complete: {count} domains, errors: {len(errors)}")


def _cleanup_logs(settings):
    retention = int(settings.get('log_retention_days', 7))
    from core.database import get_conn
    with get_conn() as conn:
        deleted = conn.execute("""
            DELETE FROM query_log 
            WHERE timestamp < datetime('now', ?)
        """, (f"-{retention} days",)).rowcount
    if deleted > 0:
        logger.info(f"Cleaned up {deleted} old query log entries")
