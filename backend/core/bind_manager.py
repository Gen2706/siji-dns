#!/usr/bin/env python3
import os, subprocess, logging
from datetime import datetime

logger = logging.getLogger(__name__)

NAMED_CONF_LOCAL = '/etc/bind/named.conf.local'
NAMED_CONF_OPT   = '/etc/bind/named.conf.options'
ZONES_DIR        = '/etc/bind/zones'

def _reload_bind():
    try:
        r = subprocess.run("rndc reload", shell=True, capture_output=True, text=True)
        if r.returncode == 0:
            return True, "BIND9 reloaded"
        subprocess.run("systemctl restart named 2>/dev/null || systemctl restart bind9 2>/dev/null",
                       shell=True)
        return True, "BIND9 restarted"
    except Exception as e:
        return False, str(e)

def _check_config():
    result = subprocess.run("named-checkconf", shell=True, capture_output=True, text=True)
    return result.returncode == 0, result.stderr

def write_named_options(settings, forwarders):
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

    content = f"""// siji-DNS managed options
// Generated: {datetime.utcnow().isoformat()}
options {{
    directory "/var/cache/bind";
    listen-on {{ any; }};
    listen-on-v6 {{ none; }};
    allow-query {{ any; }};
    allow-recursion {{ any; }};
    recursion {recursion};
    dnssec-validation {dnssec_validation};
{fwd_block}
{rate_limit}
    auth-nxdomain no;
    minimal-responses yes;
    prefetch 2;
    version "siji-DNS";
    check-names master ignore;
    check-names response ignore;
}};
"""
    with open(NAMED_CONF_OPT, 'w') as f:
        f.write(content)

def write_zone_file(zone, records):
    os.makedirs(ZONES_DIR, exist_ok=True)
    zone_name = zone['name'].rstrip('.')
    zone_file = os.path.join(ZONES_DIR, f"db.{zone_name}")
    serial = int(datetime.utcnow().strftime('%Y%m%d') + '01')

    ns = zone.get('ns') or f"ns1.{zone_name}"
    ns = ns.rstrip('.') + '.'
    email = zone.get('email') or f"hostmaster.{zone_name}"
    email = email.replace('@', '.').rstrip('.') + '.'

    lines = [
        f"; siji-DNS zone: {zone_name}",
        f"; Generated: {datetime.utcnow().isoformat()}",
        f"$ORIGIN {zone_name}.",
        f"$TTL {zone['ttl']}",
        f"@\tIN\tSOA\t{ns} {email} (",
        f"\t\t\t{serial}\t; Serial",
        f"\t\t\t{zone.get('refresh', 86400)}\t; Refresh",
        f"\t\t\t{zone.get('retry', 7200)}\t; Retry",
        f"\t\t\t{zone.get('expire', 604800)}\t; Expire",
        f"\t\t\t{zone.get('minimum', 300)}\t; Minimum TTL",
        f")",
        f"@\tIN\tNS\t{ns}",
        "",
    ]

    # Auto-tambah A record untuk NS kalau belum ada
    ns_hostname = ns.rstrip('.').replace('.' + zone_name, '')
    has_ns_a = any(r['name'] == ns_hostname and r['type'] == 'A' for r in records)
    if not has_ns_a and zone_name in ns:
        import socket
        try:
            server_ip = subprocess.run(
                "hostname -I | awk '{print $1}'",
                shell=True, capture_output=True, text=True
            ).stdout.strip()
        except Exception:
            server_ip = '127.0.0.1'
        lines.append(f"{ns_hostname}\t{zone['ttl']}\tIN\tA\t{server_ip}")
        lines.append("")

    for rec in records:
        name  = rec['name'] if rec['name'] not in ('', None) else '@'
        rtype = rec['type'].upper()
        val   = rec['value'].strip()
        ttl   = rec.get('ttl') or zone['ttl']
        prio  = rec.get('priority') or 0

        if rtype in ('NS', 'CNAME', 'PTR', 'MX'):
            if not val.endswith('.'):
                val = val + '.'
        if rtype == 'TXT':
            if not val.startswith('"'):
                val = f'"{val}"'
            lines.append(f"{name}\t{ttl}\tIN\t{rtype}\t{val}")
        elif rtype in ('MX', 'SRV'):
            lines.append(f"{name}\t{ttl}\tIN\t{rtype}\t{prio} {val}")
        else:
            lines.append(f"{name}\t{ttl}\tIN\t{rtype}\t{val}")

    content = '\n'.join(lines) + '\n'
    with open(zone_file, 'w') as f:
        f.write(content)

    # Validasi zone file
    result = subprocess.run(
        f"named-checkzone {zone_name} {zone_file}",
        shell=True, capture_output=True, text=True
    )
    if result.returncode != 0:
        logger.error(f"Zone content:\n{content}")
        logger.error(f"named-checkzone: {result.stderr}")
        os.remove(zone_file)
        raise ValueError(f"Zone validation failed: {result.stderr or result.stdout}")

    logger.info(f"Zone file written: {zone_file}")
    return zone_file

def write_named_local(zones):
    lines = [
        "// siji-DNS managed zones",
        f"// Generated: {datetime.utcnow().isoformat()}",
        "",
        "logging {",
        "    channel query_log {",
        '        file "/var/log/named/named.log" versions 3 size 20m;',
        "        severity dynamic;",
        "        print-time yes;",
        "    };",
        "    category queries { query_log; };",
        "};",
        "",
    ]
    for zone in zones:
        if not zone.get('active'):
            continue
        zone_name = zone['name'].rstrip('.')
        zone_file = os.path.join(ZONES_DIR, f"db.{zone_name}")
        zone_type = zone.get('type', 'master')
        lines += [
            f'zone "{zone_name}" {{',
            f'    type {zone_type};',
            f'    file "{zone_file}";',
            '    allow-update { none; };',
            '};',
            '',
        ]
    with open(NAMED_CONF_LOCAL, 'w') as f:
        f.write('\n'.join(lines))

def apply_all(zones, records_by_zone, settings, forwarders):
    write_named_options(settings, forwarders)
    write_named_local(zones)
    for zone in zones:
        recs = records_by_zone.get(zone['id'], [])
        try:
            write_zone_file(zone, recs)
        except ValueError as e:
            logger.error(f"Skipping zone {zone['name']}: {e}")
    ok, msg = _check_config()
    if not ok:
        raise RuntimeError(f"BIND config check failed: {msg}")
    return _reload_bind()

def get_bind_status():
    for svc in ['named', 'bind9']:
        r = subprocess.run(f"systemctl is-active {svc}",
                           shell=True, capture_output=True, text=True)
        if r.stdout.strip() == 'active':
            return {'status': 'active', 'service': svc}
    return {'status': 'inactive', 'service': 'named'}
