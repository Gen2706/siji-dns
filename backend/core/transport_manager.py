#!/usr/bin/env python3
"""
siji-DNS Transport Manager
Manages DoH (DNS-over-HTTPS), DoT (DNS-over-TLS), DoQ (DNS-over-QUIC)
using dnsdist as the frontend proxy
"""

import os
import subprocess
import logging
from datetime import datetime

logger = logging.getLogger(__name__)
DNSDIST_CONF = '/etc/dnsdist/dnsdist.conf'
DNSDIST_BLOCK_LUA = '/etc/siji-dns/blocklists/compiled/dnsdist-block.lua'


def generate_dnsdist_config(settings):
    """Generate full dnsdist.conf with DoH/DoT/DoQ support"""
    os.makedirs('/etc/dnsdist', exist_ok=True)

    doh_enabled = settings.get('doh_enabled') == '1'
    dot_enabled = settings.get('dot_enabled') == '1'
    doq_enabled = settings.get('doq_enabled') == '1'
    tls_cert    = settings.get('tls_cert', '/etc/siji-dns/tls/cert.pem')
    tls_key     = settings.get('tls_key',  '/etc/siji-dns/tls/key.pem')
    doh_port    = settings.get('doh_port',  '443')
    dot_port    = settings.get('dot_port',  '853')
    doq_port    = settings.get('doq_port',  '853')
    rate_limit  = settings.get('rate_limit_qps', '1000')

    lines = [
        f"-- siji-DNS dnsdist config",
        f"-- Generated: {datetime.utcnow().isoformat()}",
        "",
        "-- Backend: BIND9 authoritative",
        'newServer({address="127.0.0.1:53", name="bind9-auth"})',
        "",
        "-- Plain DNS listeners",
        'addLocal("0.0.0.0:53", {reusePort=true})',
        "",
    ]

    if doh_enabled and os.path.exists(tls_cert):
        lines += [
            "-- DNS-over-HTTPS (DoH)",
            f'addDOHLocal("0.0.0.0:{doh_port}", "{tls_cert}", "{tls_key}",',
            '    "/dns-query", {reusePort=true,',
            '    serverTokens="siji-DNS",',
            '    customResponseHeaders={["access-control-allow-origin"]="*"}})',
            "",
        ]

    if dot_enabled and os.path.exists(tls_cert):
        lines += [
            "-- DNS-over-TLS (DoT)",
            f'addTLSLocal("0.0.0.0:{dot_port}", "{tls_cert}", "{tls_key}",',
            '    {reusePort=true, provider="openssl"})',
            "",
        ]

    if doq_enabled and os.path.exists(tls_cert):
        lines += [
            "-- DNS-over-QUIC (DoQ)",
            f'addDOQLocal("0.0.0.0:{doq_port}", "{tls_cert}", "{tls_key}")',
            "",
        ]

    lines += [
        "-- Rate limiting (ISP mode)",
        f"addAction(MaxQPSRule({rate_limit}), TCAction())",
        "",
        "-- Load blocklist if exists",
        f'if(pcall(dofile, "{DNSDIST_BLOCK_LUA}")) then',
        '    print("siji-DNS blocklist loaded")',
        "end",
        "",
        "-- Query cache",
        f"pc = newPacketCache(100000, {{maxTTL=3600, minTTL=0}})",
        "getPool(''):setCache(pc)",
        "",
        "-- Security",
        "addAction(QTypeRule(DNSQType.ANY), TCAction())",
        "setConsoleACL({'127.0.0.1/32', '::1/128'})",
        "",
        "-- Stats",
        "webserver('0.0.0.0:8083')",
        "setWebserverConfig({password='siji-dnsdist', apiKey='siji-api-key'})",
    ]

    with open(DNSDIST_CONF, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    logger.info("dnsdist.conf written")


def reload_dnsdist():
    """Reload dnsdist configuration"""
    try:
        r = subprocess.run(
            "systemctl reload dnsdist",
            shell=True, capture_output=True, text=True
        )
        if r.returncode == 0:
            return True, "dnsdist reloaded"
        # Try restart
        r2 = subprocess.run("systemctl restart dnsdist", shell=True, capture_output=True, text=True)
        return r2.returncode == 0, r2.stderr or "dnsdist restarted"
    except Exception as e:
        return False, str(e)


def get_dnsdist_status():
    r = subprocess.run("systemctl is-active dnsdist", shell=True, capture_output=True, text=True)
    return {'status': r.stdout.strip()}


def generate_self_signed_cert(domain='siji-dns.local'):
    """Generate self-signed TLS cert for testing DoH/DoT"""
    tls_dir = '/etc/siji-dns/tls'
    os.makedirs(tls_dir, exist_ok=True)
    cert = os.path.join(tls_dir, 'cert.pem')
    key  = os.path.join(tls_dir, 'key.pem')

    cmd = (f"openssl req -x509 -newkey rsa:4096 -keyout {key} "
           f"-out {cert} -days 365 -nodes "
           f"-subj '/CN={domain}/O=siji-DNS'")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Cert generation failed: {result.stderr}")
    return cert, key
