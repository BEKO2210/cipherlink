# CipherLink Relay Server — Self-Hosting Guide

> **Ziel:** CipherLink Relay auf deinem Ubuntu Server hinter Cloudflare Tunnel hosten.
> **Domain:** `it-handwerk-stuttgart.de` → Subdomain `relay.it-handwerk-stuttgart.de`

---

## Voraussetzungen

| Was | Version | Prüfen |
|-----|---------|--------|
| Ubuntu Server | 20.04+ | `lsb_release -a` |
| Node.js | 18+ | `node -v` |
| pnpm | 8+ | `pnpm -v` |
| Cloudflare Tunnel | (cloudflared) | `cloudflared --version` |
| Git | 2.x | `git --version` |

---

## Schritt 1: Laufende Ports prüfen

```bash
# Alle belegten Ports mit Prozessnamen
sudo ss -tlnp

# Nur bestimmten Port prüfen
sudo ss -tlnp | grep :4200

# Alternativ mit lsof
sudo lsof -i -P -n | grep LISTEN
```

**Erwartete Ausgabe auf deinem Server:**

| Port | Dienst |
|------|--------|
| 80/443 | Nginx / Cloudflare Tunnel |
| 8096 | Jellyfin |
| 8920 | Jellyfin HTTPS |
| 22 | SSH |
| **4200** | **CipherLink Relay (NEU)** |

---

## Schritt 2: Node.js + pnpm installieren

Falls noch nicht vorhanden:

```bash
# Node.js 20 LTS installieren
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# pnpm global installieren
sudo npm install -g pnpm

# Prüfen
node -v    # Sollte v20.x zeigen
pnpm -v    # Sollte 8.x+ zeigen
```

---

## Schritt 3: CipherLink klonen & installieren

```bash
# In dein Projektverzeichnis wechseln
cd /opt
sudo mkdir -p cipherlink
sudo chown $USER:$USER cipherlink
cd cipherlink

# Repository klonen
git clone https://github.com/BEKO2210/cipherlink.git .

# Abhängigkeiten installieren
pnpm install

# Server bauen
cd apps/server
pnpm build   # Kompiliert TypeScript nach dist/
```

---

## Schritt 4: Server testen (lokal)

```bash
# Im apps/server Verzeichnis
cd /opt/cipherlink/apps/server

# Relay starten (Development-Modus)
PORT=4200 pnpm dev

# In einem anderen Terminal testen:
# Der Server sollte auf Port 4200 lauschen
curl -v http://localhost:4200
# Erwartung: "Upgrade Required" (weil es ein WebSocket-Server ist)
```

Drücke `Ctrl+C` um den Dev-Server zu stoppen.

---

## Schritt 5: Cloudflare Tunnel konfigurieren

Da du bereits `jellyfin.it-handwerk-stuttgart.de` über Cloudflare Tunnel laufen hast,
brauchst du nur eine **neue Route** hinzufügen.

### Option A: Cloudflare Dashboard (Zero Trust)

1. Gehe zu **Cloudflare Dashboard** → **Zero Trust** → **Access** → **Tunnels**
2. Klicke auf deinen bestehenden Tunnel → **Configure**
3. Klicke **Add a public hostname**
4. Fülle aus:
   - **Subdomain:** `relay`
   - **Domain:** `it-handwerk-stuttgart.de`
   - **Service Type:** `HTTP`
   - **URL:** `http://localhost:4200`
5. **Wichtig** — Unter **Additional application settings**:
   - Aktiviere **WebSockets** (muss aktiviert sein!)
6. Speichern

### Option B: config.yml bearbeiten (falls du CLI nutzt)

```bash
sudo nano ~/.cloudflared/config.yml
```

Füge unter `ingress` eine neue Regel hinzu (VOR dem catch-all):

```yaml
ingress:
  # Bestehend: Jellyfin
  - hostname: jellyfin.it-handwerk-stuttgart.de
    service: http://localhost:8096

  # NEU: CipherLink Relay
  - hostname: relay.it-handwerk-stuttgart.de
    service: http://localhost:4200
    originRequest:
      noTLSVerify: true

  # Catch-all (muss immer am Ende stehen)
  - service: http_status:404
```

Dann Tunnel neustarten:

```bash
sudo systemctl restart cloudflared
```

### DNS prüfen

In **Cloudflare Dashboard** → **DNS** → prüfe ob es einen CNAME-Eintrag gibt:

```
relay.it-handwerk-stuttgart.de → <dein-tunnel-id>.cfargotunnel.com
```

Falls nicht automatisch erstellt, füge ihn manuell hinzu:
- **Type:** CNAME
- **Name:** relay
- **Target:** `<dein-tunnel-id>.cfargotunnel.com`
- **Proxy:** Enabled (orange cloud)

---

## Schritt 6: Server als systemd-Service einrichten

Damit der Relay-Server bei Neustart automatisch läuft:

```bash
sudo nano /etc/systemd/system/cipherlink-relay.service
```

Inhalt:

```ini
[Unit]
Description=CipherLink Relay Server
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/opt/cipherlink/apps/server
Environment=PORT=4200
Environment=NODE_ENV=production
Environment=LOG_LEVEL=warn
Environment=ALLOW_INSECURE_TRANSPORT=true
ExecStart=/usr/bin/node dist/index.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

> **Hinweis:** `ALLOW_INSECURE_TRANSPORT=true` ist nötig, weil Cloudflare die TLS-Terminierung
> übernimmt. Der interne Traffic (localhost → cloudflared) läuft über HTTP, aber nach außen
> ist alles via Cloudflare HTTPS/WSS verschlüsselt.

**Ersetze `YOUR_USERNAME`** mit deinem echten Benutzernamen (`whoami`).

```bash
# Service aktivieren und starten
sudo systemctl daemon-reload
sudo systemctl enable cipherlink-relay
sudo systemctl start cipherlink-relay

# Status prüfen
sudo systemctl status cipherlink-relay

# Logs ansehen
sudo journalctl -u cipherlink-relay -f
```

---

## Schritt 7: Testen

### Aus dem lokalen Netzwerk:

```bash
# WebSocket Verbindung testen (braucht wscat)
npx wscat -c wss://relay.it-handwerk-stuttgart.de
# Sende: {"type":"hello","publicKey":"dGVzdA=="}
# Erwartete Antwort: {"type":"welcome"}
```

### In der CipherLink App:

1. Öffne **Settings** → **Server Connection**
2. Die URL sollte bereits `wss://relay.it-handwerk-stuttgart.de` sein
3. Tippe auf **Test Connection**
4. Grüner Status = Server läuft und ist erreichbar
5. Tippe auf **Connect**
6. Der grüne Punkt oben zeigt: Verbunden

---

## Schritt 8: Firewall (optional)

Der CipherLink Port (4200) muss **NICHT** in der Firewall geöffnet werden,
weil Cloudflare Tunnel den Traffic intern über `cloudflared` leitet.

Falls du `ufw` nutzt, sollte die Konfiguration so aussehen:

```bash
sudo ufw status
# Port 4200 muss NICHT freigegeben sein
# Cloudflare Tunnel verbindet sich outbound, nicht inbound
```

---

## Architektur-Übersicht

```
┌──────────────────────────────────────────────┐
│  User's Phone (CipherLink App)               │
│  wss://relay.it-handwerk-stuttgart.de         │
└──────────────────┬───────────────────────────┘
                   │ HTTPS/WSS (verschlüsselt)
                   ▼
┌──────────────────────────────────────────────┐
│  Cloudflare Edge (TLS-Terminierung)          │
│  relay.it-handwerk-stuttgart.de               │
└──────────────────┬───────────────────────────┘
                   │ HTTP/WS (intern, via Tunnel)
                   ▼
┌──────────────────────────────────────────────┐
│  Dein Ubuntu Server (Workstation)            │
│  cloudflared → localhost:4200                 │
│                                              │
│  ┌──────────────────────────────┐            │
│  │ CipherLink Relay (Node.js)  │            │
│  │ Port 4200 — Zero Knowledge  │            │
│  │ Sieht nur Ciphertext        │            │
│  └──────────────────────────────┘            │
│                                              │
│  ┌──────────────────────────────┐            │
│  │ Jellyfin                    │            │
│  │ Port 8096                   │            │
│  └──────────────────────────────┘            │
└──────────────────────────────────────────────┘
```

---

## Wichtige Befehle (Cheat Sheet)

```bash
# Server Status
sudo systemctl status cipherlink-relay

# Server Logs (live)
sudo journalctl -u cipherlink-relay -f

# Server neustarten
sudo systemctl restart cipherlink-relay

# Server stoppen
sudo systemctl stop cipherlink-relay

# Ports prüfen
sudo ss -tlnp | grep 4200

# Cloudflare Tunnel Status
sudo systemctl status cloudflared

# Cloudflare Tunnel Logs
sudo journalctl -u cloudflared -f

# Server updaten
cd /opt/cipherlink
git pull
pnpm install
cd apps/server && pnpm build
sudo systemctl restart cipherlink-relay
```

---

## Eigener Server für andere User

Andere Benutzer, die ihren eigenen Relay hosten wollen:

1. Diese Anleitung befolgen
2. In der CipherLink App: **Settings** → Server URL ändern → eigene URL eingeben
3. **Test Connection** drücken → grün = funktioniert

Die End-to-End-Verschlüsselung funktioniert unabhängig vom Server, weil der
Server nur verschlüsselten Ciphertext weiterleitet (Zero-Knowledge-Architektur).

---

## Troubleshooting

| Problem | Lösung |
|---------|--------|
| `Connection timed out` in App | Cloudflare Tunnel prüfen, WebSocket aktiviert? |
| `502 Bad Gateway` | CipherLink Relay läuft nicht → `systemctl status cipherlink-relay` |
| Server startet nicht | Logs prüfen: `journalctl -u cipherlink-relay -e` |
| Port 4200 belegt | `sudo ss -tlnp \| grep 4200` → anderen Port nutzen |
| DNS nicht auflösbar | CNAME in Cloudflare DNS prüfen |
| WebSocket upgrade fehlgeschlagen | In Cloudflare Tunnel-Config WebSockets aktivieren |

---

*CipherLink — by Belkis Aslani — MIT License*
