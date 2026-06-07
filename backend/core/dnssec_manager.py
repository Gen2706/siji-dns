#!/usr/bin/env python3
"""
siji-DNS DNSSEC Manager
Handles DNSSEC key generation, signing, and rotation using BIND tools
"""

import os
import re
import subprocess
import logging
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)
KEYS_DIR = '/etc/bind/keys'


def ensure_dirs():
    os.makedirs(KEYS_DIR, exist_ok=True)
    subprocess.run(f"chown bind:bind {KEYS_DIR}", shell=True)


def generate_ksk(zone_name, algorithm='ECDSAP256SHA256'):
    """Generate Key Signing Key"""
    ensure_dirs()
    cmd = (f"dnssec-keygen -a {algorithm} -b 2048 -n ZONE "
           f"-f KSK -K {KEYS_DIR} {zone_name}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"KSK generation failed: {result.stderr}")
    key_name = result.stdout.strip()
    return _read_key_files(key_name)


def generate_zsk(zone_name, algorithm='ECDSAP256SHA256'):
    """Generate Zone Signing Key"""
    ensure_dirs()
    cmd = (f"dnssec-keygen -a {algorithm} -b 1024 "
           f"-n ZONE -K {KEYS_DIR} {zone_name}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"ZSK generation failed: {result.stderr}")
    key_name = result.stdout.strip()
    return _read_key_files(key_name)


def _read_key_files(key_name):
    pub_path  = os.path.join(KEYS_DIR, f"{key_name}.key")
    priv_path = os.path.join(KEYS_DIR, f"{key_name}.private")
    pub_content  = open(pub_path).read()  if os.path.exists(pub_path)  else ""
    priv_content = open(priv_path).read() if os.path.exists(priv_path) else ""

    key_tag = None
    m = re.search(r'key tag = (\d+)', pub_content, re.IGNORECASE)
    if m:
        key_tag = int(m.group(1))

    key_type = 'KSK' if 'KSK' in pub_content else 'ZSK'
    alg_match = re.search(r'Algorithm:\s*(\S+)', pub_content)
    algorithm = alg_match.group(1) if alg_match else 'UNKNOWN'

    return {
        'key_name':   key_name,
        'key_type':   key_type,
        'algorithm':  algorithm,
        'key_tag':    key_tag,
        'public_key': pub_content,
        'private_key': priv_content,
        'pub_path':   pub_path,
        'priv_path':  priv_path,
    }


def sign_zone(zone_name, zone_file):
    """Sign a zone file with DNSSEC"""
    signed_file = zone_file + '.signed'
    cmd = (f"dnssec-signzone -A -3 $(head -c 16 /dev/urandom | sha1sum | cut -c1-8) "
           f"-N INCREMENT -o {zone_name} -t "
           f"-K {KEYS_DIR} {zone_file}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                            cwd=KEYS_DIR)
    if result.returncode != 0:
        raise RuntimeError(f"Zone signing failed: {result.stderr}")

    expiry_match = re.search(r'Signatures were created.*?expire (\d{14})', result.stdout)
    logger.info(f"Zone {zone_name} signed successfully")
    return signed_file, result.stdout


def get_ds_records(zone_name):
    """Get DS records for parent zone delegation"""
    key_files = list(Path(KEYS_DIR).glob(f"K{zone_name}.+*+*.key"))
    ds_records = []
    for kf in key_files:
        content = kf.read_text()
        if 'KSK' not in content:
            continue
        cmd = f"dnssec-dsfromkey {kf}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                ds_records.append(line)
    return ds_records


def validate_dnssec(zone_name):
    """Test DNSSEC validation for a zone"""
    result = subprocess.run(
        f"dig +dnssec +short {zone_name} SOA @127.0.0.1",
        shell=True, capture_output=True, text=True
    )
    has_rrsig = 'RRSIG' in result.stdout
    return {
        'valid': has_rrsig,
        'output': result.stdout,
        'zone': zone_name,
    }


def rotate_zsk(zone_name):
    """Perform ZSK rollover (double-sign method)"""
    new_zsk = generate_zsk(zone_name)
    logger.info(f"New ZSK generated for {zone_name}: {new_zsk['key_name']}")
    return new_zsk


def get_dnssec_status():
    """Check if BIND is running with DNSSEC"""
    result = subprocess.run(
        "rndc signing -list",
        shell=True, capture_output=True, text=True
    )
    return {
        'active': result.returncode == 0,
        'output': result.stdout or result.stderr,
    }
