#!/bin/bash
# ============================================================
#  siji-DNS Installer — All-in-One
#  Ubuntu 22.04 / 24.04 / Debian 12
#  Includes: BIND9, Unbound, dnsdist, Python, Nginx
#  Fix: systemd service, wsgi wrapper, unbound config
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

SIJI_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIJI_DIR="/opt/siji-dns"
SIJI_CONF="/etc/siji-dns"
SIJI_LOG="/var/log/siji-dns"

banner() {
  echo -e "${BOLD}${CYAN}"
  echo "  ███████╗██╗     ██╗      ██╗      ██████╗ ███╗   ██╗███████╗"
  echo "  ██╔════╝██║     ██║      ██║      ██╔══██╗████╗  ██║██╔════╝"
  echo "  ███████╗██║     ██║      ██║█████╗██║  ██║██╔██╗ ██║███████╗"
  echo "  ╚════██║██║██   ██║██    ██║╚════╝██║  ██║██║╚██╗██║╚════██║"
  echo "  ███████║██║╚█████╔╝╚█████╔╝       ██████╔╝██║ ╚████║███████║"
  echo "  ╚══════╝╚═╝ ╚════╝  ╚════╝        ╚═════╝ ╚═╝  ╚═══╝╚══════╝"
  echo -e "${NC}"
  echo -e "  ${BOLD}siji-DNS${NC} — DNS Management Platform untuk ISP"
  echo ""
}

check_root() {
  [[ $EUID -ne 0 ]] && error "Jalankan sebagai root: sudo bash install.sh"
}

install_packages() {
  info "Update package list..."
  apt-get update -qq

  info "Install BIND9..."
  apt-get install -y bind9 bind9utils bind9-doc dnsutils

  info "Install Unbound..."
  apt-get install -y unbound

  info "Install Python3..."
  apt-get install -y python3 python3-pip python3-venv

  info "Install Nginx..."
  apt-get install -y nginx

  info "Install tools tambahan..."
  apt-get install -y openssl curl wget git

  # dnsdist (opsional, untuk DoH/DoT/DoQ)
  if apt-get install -y dnsdist 2>/dev/null; then
    success "dnsdist terinstall"
  else
    warn "dnsdist tidak tersedia di repo ini, DoH/DoT/DoQ dinonaktifkan"
  fi

  success "Semua packages terinstall"
}

disable_systemd_resolved() {
  if systemctl is-active systemd-resolved &>/dev/null; then
    info "Menonaktifkan systemd-resolved (konflik port 53)..."
    systemctl disable --now systemd-resolved || true
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    success "systemd-resolved dinonaktifkan"
  fi
}

setup_dirs() {
  info "Membuat direktori..."
  mkdir -p "$SIJI_CONF/blocklists/raw"
  mkdir -p "$SIJI_CONF/blocklists/compiled"
  mkdir -p "$SIJI_CONF/tls"
  mkdir -p "$SIJI_LOG"
  mkdir -p /etc/bind/zones
  mkdir -p /etc/bind/keys
  mkdir -p /var/log/named
  mkdir -p /var/cache/bind

  chown -R bind:bind /etc/bind/zones /etc/bind/keys /var/log/named /var/cache/bind 2>/dev/null || true
  chmod 755 /etc/bind/zones /etc/bind/keys
  success "Direktori siap"
}

install_app() {
  info "Copy siji-DNS ke $SIJI_DIR..."
  mkdir -p "$SIJI_DIR"
  rsync -a --exclude='*.pyc' --exclude='__pycache__' --exclude='.git' \
    "$SIJI_SRC/" "$SIJI_DIR/"

  info "Setup Python virtual environment..."
  python3 -m venv "$SIJI_DIR/venv"
  "$SIJI_DIR/venv/bin/pip" install -q --upgrade pip
  "$SIJI_DIR/venv/bin/pip" install -q -r "$SIJI_DIR/backend/requirements.txt"

  # Buat wsgi.py wrapper (fix untuk gunicorn)
  cat > "$SIJI_DIR/backend/wsgi.py" << 'WSGI'
from app import create_app
application, socketio = create_app()
WSGI

  success "Aplikasi terinstall di $SIJI_DIR"
}

configure_bind() {
  info "Konfigurasi BIND9..."

  # Backup config lama
  [[ -f /etc/bind/named.conf.options ]] && \
    cp /etc/bind/named.conf.options "/etc/bind/named.conf.options.bak.$(date +%s)" 2>/dev/null || true

  cat > /etc/bind/named.conf.options << 'BINDCONF'
// siji-DNS managed - regenerated on apply
options {
    directory "/var/cache/bind";
    listen-on { any; };
    listen-on-v6 { none; };
    allow-query { any; };
    allow-recursion { any; };
    recursion yes;
    dnssec-validation no;
    auth-nxdomain no;
    minimal-responses yes;
    prefetch 2;
    version "siji-DNS";
};
BINDCONF

  # Pastikan named.conf.local ada
  [[ -f /etc/bind/named.conf.local ]] || \
    echo '// siji-DNS zones' > /etc/bind/named.conf.local

  systemctl enable named 2>/dev/null || systemctl enable bind9 2>/dev/null || true
  systemctl restart named 2>/dev/null || systemctl restart bind9 2>/dev/null || true

  if systemctl is-active named &>/dev/null || systemctl is-active bind9 &>/dev/null; then
    success "BIND9 aktif"
  else
    warn "BIND9 gagal start, cek: journalctl -u named"
  fi
}

configure_unbound() {
  info "Konfigurasi Unbound..."

  cat > /etc/unbound/unbound.conf << 'UNBOUNDCONF'
server:
    verbosity: 1
    interface: 127.0.0.2
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    access-control: 0.0.0.0/0 allow
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    prefetch: yes
    cache-min-ttl: 0
    cache-max-ttl: 86400
    num-threads: 2

    # siji-DNS blocklist
    include-if-possible: /etc/siji-dns/blocklists/compiled/unbound-local.conf
UNBOUNDCONF

  systemctl enable unbound
  systemctl restart unbound

  if systemctl is-active unbound &>/dev/null; then
    success "Unbound aktif"
  else
    warn "Unbound gagal start, cek: journalctl -u unbound"
  fi
}

configure_dnsdist() {
  if ! command -v dnsdist &>/dev/null; then
    warn "dnsdist tidak terinstall, skip"
    return
  fi

  info "Konfigurasi dnsdist (minimal)..."
  mkdir -p /etc/dnsdist

  cat > /etc/dnsdist/dnsdist.conf << 'DNSDISTCONF'
-- siji-DNS dnsdist - akan diregenerasi via Web UI
newServer({address="127.0.0.1:53", name="bind9"})
addLocal("0.0.0.0:5353", {reusePort=true})
setConsoleACL({"127.0.0.1/32", "::1/128"})
DNSDISTCONF

  systemctl enable dnsdist 2>/dev/null || true
  systemctl restart dnsdist 2>/dev/null || true
  success "dnsdist dikonfigurasi"
}

create_service() {
  info "Membuat systemd service siji-dns-api..."

  cat > /etc/systemd/system/siji-dns-api.service << SVCEOF
[Unit]
Description=siji-DNS Web API
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$SIJI_DIR/backend
ExecStart=$SIJI_DIR/venv/bin/gunicorn \\
    --worker-class eventlet \\
    --workers 1 \\
    --bind 0.0.0.0:5000 \\
    --timeout 120 \\
    wsgi:application
Restart=always
RestartSec=5
Environment=SIJI_DB_PATH=$SIJI_CONF/siji.db
Environment=BIND_CONFIG_DIR=/etc/bind
Environment=BIND_ZONES_DIR=/etc/bind/zones
Environment=BLOCKLIST_DIR=$SIJI_CONF/blocklists

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl daemon-reload
  systemctl enable siji-dns-api
  systemctl restart siji-dns-api

  sleep 3

  if systemctl is-active siji-dns-api &>/dev/null; then
    success "siji-DNS API aktif di port 5000"
  else
    warn "API gagal start, cek: journalctl -u siji-dns-api -n 20"
  fi
}

configure_nginx() {
  info "Konfigurasi Nginx reverse proxy..."

  cat > /etc/nginx/sites-available/siji-dns << 'NGINXCONF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
        proxy_connect_timeout 10;
    }
}
NGINXCONF

  ln -sf /etc/nginx/sites-available/siji-dns /etc/nginx/sites-enabled/siji-dns
  rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

  nginx -t && systemctl restart nginx

  if systemctl is-active nginx &>/dev/null; then
    success "Nginx aktif di port 80"
  else
    warn "Nginx gagal start"
  fi
}

setup_firewall() {
  if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    info "Buka port di UFW..."
    ufw allow 22/tcp   comment "SSH"    2>/dev/null || true
    ufw allow 53/tcp   comment "DNS"    2>/dev/null || true
    ufw allow 53/udp   comment "DNS"    2>/dev/null || true
    ufw allow 80/tcp   comment "HTTP"   2>/dev/null || true
    ufw allow 443/tcp  comment "HTTPS"  2>/dev/null || true
    ufw allow 853/tcp  comment "DoT"    2>/dev/null || true
    ufw allow 5000/tcp comment "API"    2>/dev/null || true
    success "Firewall dikonfigurasi"
  fi
}

print_summary() {
  SERVER_IP=$(hostname -I | awk '{print $1}')
  echo ""
  echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  siji-DNS berhasil diinstall!${NC}"
  echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
  echo ""
  echo -e "  ${BOLD}Web Interface:${NC}  http://${SERVER_IP}"
  echo -e "  ${BOLD}Login:${NC}          admin / siji-admin"
  echo ""
  echo -e "  ${BOLD}Status Layanan:${NC}"
  systemctl is-active named   &>/dev/null && echo -e "    ${GREEN}✓${NC} BIND9 (named)" || \
  systemctl is-active bind9   &>/dev/null && echo -e "    ${GREEN}✓${NC} BIND9" || \
    echo -e "    ${RED}✗${NC} BIND9 — cek: journalctl -u named"
  systemctl is-active unbound &>/dev/null && echo -e "    ${GREEN}✓${NC} Unbound" || \
    echo -e "    ${RED}✗${NC} Unbound — cek: journalctl -u unbound"
  systemctl is-active siji-dns-api &>/dev/null && echo -e "    ${GREEN}✓${NC} siji-DNS API" || \
    echo -e "    ${RED}✗${NC} siji-DNS API — cek: journalctl -u siji-dns-api"
  systemctl is-active nginx &>/dev/null && echo -e "    ${GREEN}✓${NC} Nginx" || \
    echo -e "    ${RED}✗${NC} Nginx"
  echo ""
  echo -e "  ${BOLD}⚠ Segera ganti password default!${NC}"
  echo -e "  Pengaturan → Akun → Ganti Password"
  echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
}

# ─── Main ────────────────────────────────────────────────────────────────────
banner
check_root
install_packages
disable_systemd_resolved
setup_dirs
install_app
configure_bind
configure_unbound
configure_dnsdist
create_service
configure_nginx
setup_firewall
print_summary
