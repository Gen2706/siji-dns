# siji-DNS v2.0 🌐

**DNS Management Platform untuk ISP & Enterprise**

> *siji* — bahasa Jawa untuk "satu". Satu platform untuk semua kebutuhan DNS.

## Fitur

| Fitur | Teknologi |
|-------|-----------|
| Authoritative DNS | BIND9 |
| Recursive Resolver | Unbound |
| DNS Forwarding | BIND9 forwarders |
| DNS Filtering / Blocklist | Unbound local-data (tanpa RPZ) |
| DNSSEC | dnssec-keygen + dnssec-signzone |
| DoH / DoT / DoQ | dnsdist |
| Web Interface | Flask + Vanilla JS |
| Query Log Real-time | BIND9 log parser |
| ISP Features | Rate limiting, audit log |

## Instalasi

### Persyaratan
- Ubuntu 22.04 / 24.04 atau Debian 12
- Minimal 2GB RAM, 2 CPU core
- Root access

### Install

```bash
git clone https://github.com/Gen2706/siji-dns.git
cd siji-dns
sudo bash installer/install.sh
```

### Ganti port web (default: 2706)

```bash
sudo SIJI_PORT=8080 bash installer/install.sh
```

### Akses

```
http://SERVER_IP:2706
Login: admin / siji-admin
```

> ⚠️ **Segera ganti password default** setelah login pertama!

## Manajemen Service

```bash
# Status
systemctl status siji-dns-api siji-dns-logger named unbound nginx

# Restart semua
systemctl restart siji-dns-api siji-dns-logger named

# Log real-time
journalctl -u siji-dns-api -f
journalctl -u siji-dns-logger -f
tail -f /var/log/named/named.log
```

## Arsitektur

```
Client DNS Query (port 53)
         │
         ▼
      BIND9 (Authoritative + Recursive)
         │
         ▼
   siji-DNS Logger ──► SQLite DB ◄── siji-DNS API (port 5000)
                                              │
                                              ▼
                                        Nginx (port 2706)
                                              │
                                              ▼
                                        Web Browser
```

## Lisensi

MIT License
