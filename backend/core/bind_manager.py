#!/usr/bin/env python3
"""
siji-DNS BIND9 Config Manager
Generates and manages BIND9 named.conf and zone files
"""

import os
import re
import subprocess
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

NAMED_CONF_LOCAL  = '/etc/bind/named.conf.local'
NAMED_CONF_OPT    = '/etc/bind/named.conf.options'
ZONES_DIR         = '/etc/bind/zones'


# ─── Helpers ────────────────────────────────────────────────────────────────

def _run(cmd, check=True):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{result.stderr}")
    return result.stdout.strip()

def _reload_bind():
    try:
        _run("rndc reload")
        return True, "BIND9 reloaded successfully"
    except Exception as e:
        logger.error(f"BIND reload failed: {e}")
        return False, str(e)

def _check_config():
    result = subprocess.run("named-checkconf", shell=True, capture_output=True, text=True)
    return result.returncode == 0, result.stderr

def _increment_serial(zone_name):
    """Generate YYYYMMDDNN-style serial"""
    today = datetime.utcnow().strftime('%Y%m%d')
    return int(today + '01')


# ─── Options (named.conf.options) ───────────────────────────────────────────

def write_named_options(settings, forwarders):
    """Generate named.conf.options from settings"""
    os.makedirs(os.path.dirname(NAMED_CONF_OPT), exist_ok=True)

    fwd_block = ""
    if settings.get('forwarding_enabled') == '1' and forwarders:
        fwd_lines = "\n".join(f"        {f['ip']} port {f['port']};" for f in forwarders)
        fwd_block = f"""
    forwarders {{
{fwd_lines}
    }};
    forward {'only' if settings.get('forward_only') == '1' else 'first'};"""

    dnssec_validation = 'auto' if settings.get('dnssec_enabled') == '1' else 'no'
    recursion = 'yes' if settings.get('recursive_enabled') == '1' else 'no'
    
    rate_limit = ""
    if settings.get('rate_limiting') == '1':
        qps = settings.get('rate_limit_qps', '1000')
        rate_limit = f"""
    rate-limit {{
        responses-per-second {qps};
        window 5;
    }};"""

    content = f"""// siji-DNS managed options - do not edit manually
// Generated: {datetime.utcnow().isoformat()}

options {{
    directory "/var/cache/bind";
    listen-on {{ any; }};
    listen-on-v6 {{ any; }};
    allow-query {{ any; }};
    allow-recursion {{ any; }};
    recursion {recursion};
    dnssec-validation {dnssec_validation};
{fwd_block}
{rate_limit}
    querylog {'yes' if settings.get('query_logging') == '1' else 'no'};
    version "siji-DNS";
    auth-nxdomain no;
    minimal-responses yes;
    prefetch 2;
}};
"""
    with open(NAMED_CONF_OPT, 'w') as f:
        f.write(content)
    logger.info("named.conf.options written")


# ─── Zone file generation ────────────────────────────────────────────────────

def write_zone_file(zone, records):
    os.makedirs(ZONES_DIR, exist_ok=True)
    zone_file = os.path.join(ZONES_DIR, f"db.{zone['name']}")
    serial = _increment_serial(zone['name'])
    ns = zone.get('ns', f"ns1.{zone['name']}")
    email = zone.get('email', f"hostmaster.{zone['name']}").replace('@', '.')

    lines = [
        f"; siji-DNS zone file for {zone['name']}",
        f"; Generated: {datetime.utcnow().isoformat()}",
        f"$ORIGIN {zone['name']}.",
        f"$TTL {zone['ttl']}",
        f"@ IN SOA {ns}. {email}. (",
        f"    {serial}  ; Serial",
        f"    {zone['refresh']}      ; Refresh",
        f"    {zone['retry']}       ; Retry",
        f"    {zone['expire']}  ; Expire",
        f"    {zone['minimum']}     ; Minimum TTL",
        f")",
        "",
    ]

    for rec in records:
        name  = rec['name'] if rec['name'] != '@' else '@'
        rtype = rec['type']
        val   = rec['value']
        ttl   = rec.get('ttl', zone['ttl'])
        prio  = rec.get('priority', 0)

        if rtype in ('MX', 'SRV'):
            lines.append(f"{name}\t{ttl}\tIN\t{rtype}\t{prio} {val}")
        elif rtype == 'TXT':
            # wrap in quotes if not already
            if not val.startswith('"'):
                val = f'"{val}"'
            lines.append(f"{name}\t{ttl}\tIN\t{rtype}\t{val}")
        else:
            lines.append(f"{name}\t{ttl}\tIN\t{rtype}\t{val}")

    with open(zone_file, 'w') as f:
        f.write('\n'.join(lines) + '\n')

    # Validate
    result = subprocess.run(
        f"named-checkzone {zone['name']} {zone_file}",
        shell=True, capture_output=True, text=True
    )
    if result.returncode != 0:
        os.remove(zone_file)
        raise ValueError(f"Zone validation failed: {result.stderr}")

    logger.info(f"Zone file written: {zone_file}")
    return zone_file


def write_named_local(zones):
    """Generate named.conf.local with all zone declarations"""
    lines = [
        "// siji-DNS managed zones - do not edit manually",
        f"// Generated: {datetime.utcnow().isoformat()}",
        "",
    ]
    for zone in zones:
        if not zone['active']:
            continue
        zone_type = zone.get('type', 'master')
        zone_file = os.path.join(ZONES_DIR, f"db.{zone['name']}")
        lines += [
            f'zone "{zone["name"]}" {{',
            f'    type {zone_type};',
            f'    file "{zone_file}";',
            '    allow-update { none; };' if zone_type == 'master' else '',
            '    notify yes;' if zone_type == 'master' else '',
            '};',
            '',
        ]

    with open(NAMED_CONF_LOCAL, 'w') as f:
        f.write('\n'.join(lines))
    logger.info("named.conf.local written")


def apply_all(zones, records_by_zone, settings, forwarders):
    """Full config regeneration"""
    write_named_options(settings, forwarders)
    write_named_local(zones)
    for zone in zones:
        recs = records_by_zone.get(zone['id'], [])
        if recs is not None:
            try:
                write_zone_file(zone, recs)
            except ValueError as e:
                logger.error(f"Skipping zone {zone['name']}: {e}")

    ok, msg = _check_config()
    if not ok:
        raise RuntimeError(f"BIND config check failed: {msg}")

    return _reload_bind()


def get_bind_status():
    r = subprocess.run("systemctl is-active named", shell=True, capture_output=True, text=True)
    status = r.stdout.strip()
    r2 = subprocess.run("systemctl show named --property=ActiveEnterTimestamp",
                        shell=True, capture_output=True, text=True)
    uptime = r2.stdout.strip().replace('ActiveEnterTimestamp=', '')
    return {'status': status, 'uptime': uptime}
