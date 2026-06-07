#!/usr/bin/env python3
"""
siji-DNS BIND9 Log Parser
Membaca log BIND9 real-time dan simpan ke database
"""
import re, time, sqlite3, os
from datetime import datetime

DB_PATH  = os.environ.get('SIJI_DB_PATH', '/etc/siji-dns/siji.db')
LOG_FILE = '/var/log/named/named.log'

QUERY_RE = re.compile(
    r'client\s+(?:@\S+\s+)?(\d+\.\d+\.\d+\.\d+)#\d+\s+\(([^)]+)\):\s+query:\s+(\S+)\s+IN\s+(\S+)'
)

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def parse_line(line):
    m = QUERY_RE.search(line)
    if not m:
        return None
    return m.group(1), m.group(3).rstrip('.'), m.group(4)

def is_blocked(conn, domain):
    row = conn.execute(
        "SELECT action FROM blocked_domains WHERE domain=? OR ? LIKE '%.' || domain",
        (domain, domain)
    ).fetchone()
    if row:
        return True
    return False

def tail_follow(filepath):
    while not os.path.exists(filepath):
        print(f"Waiting for {filepath}...", flush=True)
        time.sleep(5)
    with open(filepath, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.1)

def main():
    print(f"siji-DNS log parser started, watching {LOG_FILE}", flush=True)
    conn = get_conn()
    batch = []
    last_flush = time.time()

    for line in tail_follow(LOG_FILE):
        parsed = parse_line(line)
        if not parsed:
            continue
        client_ip, query_name, query_type = parsed
        blocked = is_blocked(conn, query_name)
        batch.append((
            client_ip, query_name, query_type,
            'NOERROR', None, int(blocked), 'udp',
            datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        ))

        if len(batch) >= 50 or (time.time() - last_flush) >= 2:
            try:
                conn.executemany("""
                    INSERT INTO query_log
                    (client_ip, query_name, query_type, response, latency_ms, blocked, protocol, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, batch)
                conn.commit()
                batch.clear()
                last_flush = time.time()
            except Exception as e:
                print(f"DB error: {e}", flush=True)
                conn = get_conn()

if __name__ == '__main__':
    main()
