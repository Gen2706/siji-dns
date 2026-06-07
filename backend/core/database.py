#!/usr/bin/env python3
"""
siji-DNS Database Layer
SQLite-based persistence for zones, records, blocklists, settings
"""

import sqlite3
import os
import hashlib
import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)

_db_path = None

def init_db(app):
    global _db_path
    _db_path = app.config['DATABASE_PATH']
    os.makedirs(os.path.dirname(_db_path), exist_ok=True)
    with get_conn() as conn:
        _create_tables(conn)
        _seed_defaults(conn)
    logger.info(f"Database initialized at {_db_path}")

@contextmanager
def get_conn():
    conn = sqlite3.connect(_db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def _create_tables(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT UNIQUE NOT NULL,
        password    TEXT NOT NULL,
        role        TEXT NOT NULL DEFAULT 'viewer',
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login  DATETIME
    );

    CREATE TABLE IF NOT EXISTS zones (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT UNIQUE NOT NULL,
        type        TEXT NOT NULL DEFAULT 'master',
        ttl         INTEGER DEFAULT 3600,
        serial      INTEGER DEFAULT 1,
        refresh     INTEGER DEFAULT 86400,
        retry       INTEGER DEFAULT 7200,
        expire      INTEGER DEFAULT 604800,
        minimum     INTEGER DEFAULT 300,
        ns          TEXT,
        email       TEXT,
        dnssec      INTEGER DEFAULT 0,
        active      INTEGER DEFAULT 1,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS records (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        zone_id     INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        type        TEXT NOT NULL,
        value       TEXT NOT NULL,
        ttl         INTEGER DEFAULT 3600,
        priority    INTEGER DEFAULT 0,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS forwarders (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        ip          TEXT NOT NULL,
        port        INTEGER DEFAULT 53,
        protocol    TEXT DEFAULT 'udp',
        priority    INTEGER DEFAULT 10,
        enabled     INTEGER DEFAULT 1,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS blocklists (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        source_type TEXT NOT NULL DEFAULT 'url',
        source_url  TEXT,
        entries     TEXT,
        enabled     INTEGER DEFAULT 1,
        last_updated DATETIME,
        entry_count INTEGER DEFAULT 0,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS blocked_domains (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        domain      TEXT NOT NULL,
        blocklist_id INTEGER REFERENCES blocklists(id) ON DELETE CASCADE,
        action      TEXT DEFAULT 'nxdomain',
        redirect_ip TEXT,
        added_at    DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_blocked_domains ON blocked_domains(domain);

    CREATE TABLE IF NOT EXISTS whitelist (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        domain      TEXT UNIQUE NOT NULL,
        added_by    TEXT,
        reason      TEXT,
        added_at    DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS dnssec_keys (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        zone_id     INTEGER REFERENCES zones(id) ON DELETE CASCADE,
        key_type    TEXT NOT NULL,
        algorithm   TEXT NOT NULL,
        key_tag     INTEGER,
        public_key  TEXT,
        private_key TEXT,
        activated   DATETIME,
        expires     DATETIME,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS settings (
        key         TEXT PRIMARY KEY,
        value       TEXT,
        category    TEXT DEFAULT 'general',
        updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS query_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        client_ip   TEXT,
        query_name  TEXT,
        query_type  TEXT,
        response    TEXT,
        latency_ms  INTEGER,
        blocked     INTEGER DEFAULT 0,
        protocol    TEXT DEFAULT 'udp',
        timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_query_log_ts ON query_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_query_log_blocked ON query_log(blocked);

    CREATE TABLE IF NOT EXISTS audit_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user        TEXT,
        action      TEXT,
        target      TEXT,
        detail      TEXT,
        ip          TEXT,
        timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

def _seed_defaults(conn):
    # Default admin user (password: siji-admin)
    pw_hash = hashlib.sha256("siji-admin".encode()).hexdigest()
    conn.execute("""
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES ('admin', ?, 'admin')
    """, (pw_hash,))

    defaults = [
        ('resolver_enabled',    '1',            'resolver'),
        ('recursive_enabled',   '1',            'resolver'),
        ('forwarding_enabled',  '0',            'forwarding'),
        ('filtering_enabled',   '1',            'filtering'),
        ('filter_action',       'nxdomain',     'filtering'),
        ('filter_redirect_ip',  '0.0.0.0',      'filtering'),
        ('dnssec_enabled',      '0',            'dnssec'),
        ('doh_enabled',         '0',            'transport'),
        ('doh_port',            '443',          'transport'),
        ('dot_enabled',         '0',            'transport'),
        ('dot_port',            '853',          'transport'),
        ('doq_enabled',         '0',            'transport'),
        ('doq_port',            '853',          'transport'),
        ('tls_cert',            '',             'transport'),
        ('tls_key',             '',             'transport'),
        ('query_logging',       '1',            'logging'),
        ('log_retention_days',  '7',            'logging'),
        ('isp_mode',            '1',            'isp'),
        ('rate_limiting',       '1',            'isp'),
        ('rate_limit_qps',      '1000',         'isp'),
    ]
    conn.executemany("""
        INSERT OR IGNORE INTO settings (key, value, category)
        VALUES (?, ?, ?)
    """, defaults)

    # Default public blocklist
    conn.execute("""
        INSERT OR IGNORE INTO blocklists (name, source_type, source_url, enabled)
        VALUES ('OISD Basic', 'url', 'https://basic.oisd.nl/domainswild', 1)
    """)
