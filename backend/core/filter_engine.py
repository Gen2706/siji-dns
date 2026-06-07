#!/usr/bin/env python3
"""
siji-DNS Filtering Engine
Blocklist-based DNS filtering WITHOUT RPZ.
Uses Unbound's local-data or dnsdist ACL for blocking.
"""

import os
import re
import gzip
import logging
import requests
import subprocess
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

BLOCKLIST_DIR     = '/etc/siji-dns/blocklists'
UNBOUND_LOCAL_DATA= '/etc/siji-dns/blocklists/compiled/unbound-local.conf'
DNSDIST_BLOCK_LUA = '/etc/siji-dns/blocklists/compiled/dnsdist-block.lua'
HOSTS_FILE_OUT    = '/etc/siji-dns/blocklists/compiled/blocked-hosts.txt'


def ensure_dirs():
    os.makedirs(os.path.join(BLOCKLIST_DIR, 'compiled'), exist_ok=True)
    os.makedirs(os.path.join(BLOCKLIST_DIR, 'raw'), exist_ok=True)


def fetch_blocklist(source_url, list_id):
    """Download and parse a blocklist from URL"""
    ensure_dirs()
    raw_path = os.path.join(BLOCKLIST_DIR, 'raw', f"list_{list_id}.txt")
    try:
        resp = requests.get(source_url, timeout=30, 
                           headers={'User-Agent': 'siji-DNS/1.0'})
        resp.raise_for_status()
        with open(raw_path, 'wb') as f:
            f.write(resp.content)
        domains = parse_raw_blocklist(raw_path)
        return domains, None
    except Exception as e:
        logger.error(f"Failed to fetch blocklist {source_url}: {e}")
        return [], str(e)


def parse_raw_blocklist(filepath):
    """Parse various blocklist formats into a set of domains"""
    domains = set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('!'):
                    continue
                # Hosts file format: 0.0.0.0 example.com or 127.0.0.1 example.com
                if re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+', line):
                    parts = line.split()
                    if len(parts) >= 2:
                        domain = parts[1].lower()
                        if is_valid_domain(domain) and domain not in ('localhost', '0.0.0.0', '127.0.0.1'):
                            domains.add(domain)
                # Adblock format: ||example.com^
                elif line.startswith('||') and '^' in line:
                    domain = line.split('||')[1].split('^')[0].lower()
                    if is_valid_domain(domain):
                        domains.add(domain)
                # Plain domain list
                elif is_valid_domain(line):
                    domains.add(line.lower())
                # Wildcard: *.example.com
                elif line.startswith('*.'):
                    domain = line[2:]
                    if is_valid_domain(domain):
                        domains.add(domain)
    except Exception as e:
        logger.error(f"Error parsing blocklist {filepath}: {e}")
    return domains


def is_valid_domain(domain):
    if not domain or len(domain) > 253:
        return False
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def compile_unbound_config(all_domains, action='nxdomain', redirect_ip='0.0.0.0'):
    """Generate Unbound local-data config for blocked domains"""
    ensure_dirs()
    lines = [
        "# siji-DNS compiled blocklist for Unbound",
        f"# Generated: {datetime.utcnow().isoformat()}",
        f"# Total entries: {len(all_domains)}",
        "",
        "server:",
    ]

    for domain in sorted(all_domains):
        if action == 'nxdomain':
            lines.append(f'    local-zone: "{domain}." always_nxdomain')
        elif action == 'nodata':
            lines.append(f'    local-zone: "{domain}." always_nodata')
        elif action == 'redirect' and redirect_ip:
            lines.append(f'    local-zone: "{domain}." redirect')
            lines.append(f'    local-data: "{domain}. A {redirect_ip}"')
        elif action == 'refuse':
            lines.append(f'    local-zone: "{domain}." always_refuse')

    with open(UNBOUND_LOCAL_DATA, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    logger.info(f"Unbound block config written: {len(all_domains)} domains")


def compile_dnsdist_lua(all_domains, action='nxdomain', redirect_ip='0.0.0.0'):
    """Generate dnsdist Lua block rules"""
    ensure_dirs()
    lines = [
        "-- siji-DNS compiled blocklist for dnsdist",
        f"-- Generated: {datetime.utcnow().isoformat()}",
        f"-- Total entries: {len(all_domains)}",
        "",
        "blocked = newSuffixMatchNode()",
    ]

    for domain in sorted(all_domains):
        lines.append(f'blocked:add(newDNSName("{domain}."))')

    lines += [
        "",
        "addAction(SuffixMatchNodeRule(blocked),",
    ]
    if action == 'nxdomain':
        lines.append("    RCodeAction(DNSRCode.NXDOMAIN))")
    elif action == 'nodata':
        lines.append("    RCodeAction(DNSRCode.NOERROR))")
    elif action == 'redirect' and redirect_ip:
        lines.append(f'    SpoofAction("{redirect_ip}"))')
    elif action == 'refuse':
        lines.append("    RCodeAction(DNSRCode.REFUSED))")

    with open(DNSDIST_BLOCK_LUA, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    logger.info(f"dnsdist block Lua written: {len(all_domains)} domains")


def reload_unbound():
    """Tell Unbound to reload its config"""
    try:
        r = subprocess.run("unbound-control reload", shell=True,
                           capture_output=True, text=True)
        if r.returncode == 0:
            return True, "Unbound reloaded"
        return False, r.stderr
    except Exception as e:
        return False, str(e)


def rebuild_all_blocklists(blocklists_rows, settings):
    """Full rebuild: fetch + compile + reload"""
    all_domains = set()
    errors = []

    for bl in blocklists_rows:
        if not bl['enabled']:
            continue
        if bl['source_type'] == 'url' and bl['source_url']:
            domains, err = fetch_blocklist(bl['source_url'], bl['id'])
            if err:
                errors.append(f"{bl['name']}: {err}")
            all_domains.update(domains)
        elif bl['source_type'] == 'custom' and bl['entries']:
            for line in bl['entries'].split('\n'):
                d = line.strip()
                if is_valid_domain(d):
                    all_domains.add(d.lower())

    action = settings.get('filter_action', 'nxdomain')
    redirect_ip = settings.get('filter_redirect_ip', '0.0.0.0')

    compile_unbound_config(all_domains, action, redirect_ip)
    compile_dnsdist_lua(all_domains, action, redirect_ip)

    ok, msg = reload_unbound()
    return len(all_domains), errors, ok, msg


def check_domain_blocked(domain, db_conn):
    """Check if a domain is in the blocked list"""
    # Check whitelist first
    row = db_conn.execute(
        "SELECT id FROM whitelist WHERE domain = ? OR ? LIKE '%.' || domain",
        (domain, domain)
    ).fetchone()
    if row:
        return False, 'whitelisted'

    # Check blocked_domains
    row = db_conn.execute(
        "SELECT action FROM blocked_domains WHERE domain = ? OR ? LIKE '%.' || domain",
        (domain, domain)
    ).fetchone()
    if row:
        return True, row['action']

    return False, None
