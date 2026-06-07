#!/usr/bin/env python3
import os, re, subprocess, logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)
KEYS_DIR = '/etc/bind/keys'

def ensure_dirs():
    os.makedirs(KEYS_DIR, exist_ok=True)

def generate_ksk(zone_name, algorithm='ECDSAP256SHA256'):
    ensure_dirs()
    cmd = f"dnssec-keygen -a {algorithm} -n ZONE -f KSK -K {KEYS_DIR} {zone_name}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"KSK generation failed: {result.stderr}")
    return _read_key_files(result.stdout.strip())

def generate_zsk(zone_name, algorithm='ECDSAP256SHA256'):
    ensure_dirs()
    cmd = f"dnssec-keygen -a {algorithm} -n ZONE -K {KEYS_DIR} {zone_name}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"ZSK generation failed: {result.stderr}")
    return _read_key_files(result.stdout.strip())

def _read_key_files(key_name):
    pub_path  = os.path.join(KEYS_DIR, f"{key_name}.key")
    priv_path = os.path.join(KEYS_DIR, f"{key_name}.private")
    pub_content  = open(pub_path).read()  if os.path.exists(pub_path)  else ""
    priv_content = open(priv_path).read() if os.path.exists(priv_path) else ""
    key_tag = None
    m = re.search(r'\+(\d+)\.key', pub_path)
    if m: key_tag = int(m.group(1))
    key_type = 'KSK' if '257' in pub_content else 'ZSK'
    alg_match = re.search(r'ECDSAP\w+|RSASHA\w+|ED\w+', pub_content)
    algorithm = alg_match.group(0) if alg_match else 'ECDSAP256SHA256'
    return {
        'key_name': key_name, 'key_type': key_type, 'algorithm': algorithm,
        'key_tag': key_tag, 'public_key': pub_content, 'private_key': priv_content
    }

def sign_zone(zone_name, zone_file):
    # Fix permission key files
    subprocess.run(f"chmod 644 {KEYS_DIR}/*.key {KEYS_DIR}/*.private 2>/dev/null || true",
                   shell=True)
    zone_dir      = os.path.dirname(zone_file)
    zone_basename = os.path.basename(zone_file)
    cmd = f"dnssec-signzone -S -K {KEYS_DIR} -o {zone_name} {zone_basename}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=zone_dir)
    if result.returncode != 0:
        raise RuntimeError(f"Zone signing failed: {result.stderr or result.stdout}")
    signed_file = zone_file + '.signed'
    logger.info(f"Zone {zone_name} signed")
    return signed_file, result.stdout

def get_ds_records(zone_name):
    key_files = list(Path(KEYS_DIR).glob(f"K{zone_name}.+*+*.key"))
    ds_records = []
    for kf in key_files:
        content = kf.read_text()
        if '257' not in content:
            continue
        result = subprocess.run(f"dnssec-dsfromkey {kf}",
                                shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            ds_records.extend(result.stdout.strip().split('\n'))
    return ds_records

def validate_dnssec(zone_name):
    result = subprocess.run(
        f"dig +dnssec +short {zone_name} SOA @127.0.0.1",
        shell=True, capture_output=True, text=True
    )
    return {'valid': 'RRSIG' in result.stdout, 'output': result.stdout, 'zone': zone_name}

def rotate_zsk(zone_name):
    return generate_zsk(zone_name)

def get_dnssec_status():
    result = subprocess.run("which dnssec-keygen", shell=True, capture_output=True, text=True)
    available = result.returncode == 0
    return {'active': available, 'output': result.stdout.strip() or 'not found'}
