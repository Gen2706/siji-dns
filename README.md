# siji-DNS 🌐

**DNS Management Platform untuk ISP & Enterprise**

> *siji* — bahasa Jawa untuk "satu". Satu platform untuk semua kebutuhan DNS.

---

## Fitur Lengkap

| Fitur | Teknologi | Status |
|-------|-----------|--------|
| Authoritative DNS | BIND9 | ✅ |
| Recursive Resolver | Unbound | ✅ |
| DNS Forwarding | BIND9 forwarders | ✅ |
| DNS Filtering / Blocklist | Unbound local-data + dnsdist | ✅ (tanpa RPZ) |
| DNSSEC | dnssec-keygen + dnssec-signzone | ✅ |
| DNS-over-HTTPS (DoH) | dnsdist | ✅ |
| DNS-over-TLS (DoT) | dnsdist | ✅ |
| DNS-over-QUIC (DoQ) | dnsdist | ✅ |
| Web Interface | Flask + Vanilla JS | ✅ |
| ISP Features | Rate limiting, query log | ✅ |

---

## Instalasi Cepat

### Persyaratan
- Ubuntu 22.04 / 24.04 atau Debian 12
- Minimal 2GB RAM, 2 CPU core
- Root access
- Port 53, 80, 443, 853 tersedia

### Langkah Instalasi

```bash
# Clone atau extract siji-DNS
git clone https://github.com/your-repo/siji-dns.git
cd siji-dns

# Jalankan installer
sudo bash installer/install.sh
```

Setelah selesai, buka browser: `http://SERVER_IP`

**Login default:** `admin` / `siji-admin`

> ⚠️ **Segera ganti password default** di Pengaturan → Akun

---

## Arsitektur

```
Client Query (UDP/TCP port 53)
        │
        ▼
  ┌─────────────┐
  │   dnsdist   │  ← DoH/DoT/DoQ frontend (port 443/853)
  └──────┬──────┘
         │
    ┌────┴─────┐
    │          │
    ▼          ▼
 ┌──────┐  ┌────────┐
 │BIND9 │  │Unbound │
 │Auth  │  │Recurse │
 └──────┘  └────────┘
         │
         ▼
  ┌─────────────────┐
  │   siji-DNS API  │  ← Web GUI (port 5000/80)
  │   Flask + SQLite│
  └─────────────────┘
```

### Komponen

| Komponen | Peran | Port |
|----------|-------|------|
| BIND9 | Authoritative DNS, zone management | 53 |
| Unbound | Recursive resolver, blocklist filtering | 127.0.0.2:53 |
| dnsdist | DoH/DoT/DoQ proxy, rate limiting | 443, 853, 5353 |
| Flask API | Web backend, config generator | 5000 |
| Nginx | Reverse proxy ke Flask | 80 |

---

## Filtering tanpa RPZ

siji-DNS menggunakan dua metode filtering yang **tidak bergantung pada RPZ**:

### 1. Unbound `local-data` / `local-zone`
```conf
server:
    local-zone: "ads.example.com." always_nxdomain
    local-zone: "tracking.example.com." always_nxdomain
```
- Format blocklist yang didukung: Hosts file, Adblock, domain list
- Sumber populer: OISD, StevenBlack, abuse.ch, dan lainnya

### 2. dnsdist Lua Rules
```lua
blocked = newSuffixMatchNode()
blocked:add(newDNSName("ads.example.com."))
addAction(SuffixMatchNodeRule(blocked), RCodeAction(DNSRCode.NXDOMAIN))
```

---

## DNS-over-HTTPS / DoT / DoQ

### Konfigurasi dnsdist

siji-DNS otomatis membuat konfigurasi dnsdist dengan:
- Self-signed certificate (untuk testing)
- Let's Encrypt support (production)
- HTTP/2 untuk DoH
- TLS 1.3 untuk DoT
- QUIC untuk DoQ

### Uji DoH
```bash
curl -s -H "accept: application/dns-json" \
  "https://SERVER_IP/dns-query?name=example.com&type=A" \
  --insecure | python3 -m json.tool
```

### Uji DoT
```bash
kdig @SERVER_IP +tls example.com A
```

---

## DNSSEC

```bash
# Via Web UI: Zones → Pilih zone → DNSSEC → Generate Keys → Sign Zone

# Atau manual:
dnssec-keygen -a ECDSAP256SHA256 -n ZONE example.com
dnssec-signzone -A -o example.com /etc/bind/zones/db.example.com
```

Submit DS record ke registrar untuk mengaktifkan chain of trust.

---

## Mode ISP

Fitur khusus untuk ISP/operator:

- **Rate Limiting** — batasi queries per detik per klien (cegah DDoS)
- **Query Logging** — log semua query untuk analitik
- **Blocklist besar** — support jutaan domain (OISD full: ~1.8 juta domain)
- **Multi-zone** — kelola ribuan zone authoritative
- **Audit log** — semua perubahan konfigurasi dicatat

---

## Manajemen Layanan

```bash
# Status semua layanan
systemctl status siji-dns-api bind9 unbound dnsdist

# Restart
systemctl restart siji-dns-api
systemctl restart bind9

# Log real-time
journalctl -u siji-dns-api -f
journalctl -u bind9 -f
tail -f /var/log/siji-dns/api.log

# Reload BIND (tanpa restart)
rndc reload
```

---

## Konfigurasi Manual

Semua konfigurasi dikelola otomatis via Web UI, namun file-file berikut juga bisa diedit manual:

| File | Fungsi |
|------|--------|
| `/etc/bind/named.conf.options` | BIND9 options (digenerate ulang saat apply) |
| `/etc/bind/named.conf.local` | Deklarasi zones |
| `/etc/bind/zones/db.<zone>` | Zone files |
| `/etc/unbound/unbound.conf` | Unbound config |
| `/etc/dnsdist/dnsdist.conf` | dnsdist config |
| `/etc/siji-dns/blocklists/compiled/unbound-local.conf` | Compiled blocklist |
| `/etc/siji-dns/siji.db` | SQLite database |

---

## Lisensi

MIT License — bebas digunakan, dimodifikasi, dan didistribusikan.

---

*Dibuat dengan ❤️ untuk komunitas DNS Indonesia*
