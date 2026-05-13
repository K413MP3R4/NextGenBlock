# Fonctionnalités de NextGenBlock

## Vue comparative

| Fonctionnalité                          | PeerBlock | Windows Defender Firewall | GlassWire | pfSense (référence pro) | **NextGenBlock** |
|------------------------------------------|-----------|---------------------------|-----------|-------------------------|------------------|
| Blocage IP par listes I-Blocklist        | ✅        | ❌                        | ❌        | ✅ (pfBlockerNG)        | ✅               |
| Format CIDR moderne                      | ❌        | ✅                        | ✅        | ✅                      | ✅               |
| IPv6                                      | ❌        | ✅                        | ✅        | ✅                      | ✅               |
| Pilote noyau maintenu                    | ❌        | ✅                        | ✅        | ✅                      | ✅ (WinDivert)   |
| Règles utilisateur granulaires           | ❌        | ✅                        | ⚠         | ✅                      | ✅               |
| Filtrage par application                 | ❌        | ✅                        | ✅        | ⚠ (limité)              | ✅               |
| Deep Packet Inspection                   | ❌        | ❌                        | ❌        | ✅ (Suricata)           | ✅               |
| IDS/IPS comportemental                   | ❌        | ❌                        | ❌        | ✅                      | ✅               |
| Port-scan / brute-force detection        | ❌        | ❌                        | ❌        | ✅                      | ✅               |
| Auto-ban (fail2ban-like)                 | ❌        | ❌                        | ❌        | ✅                      | ✅               |
| Filtrage DNS / sinkhole                  | ❌        | ❌                        | ❌        | ✅ (pfBlockerNG)        | ✅               |
| GeoIP / blocage par pays                 | ❌        | ❌                        | ⚠         | ✅                      | ✅               |
| Threat Intelligence (flux IoC)           | ❌        | ❌                        | ❌        | ✅                      | ✅               |
| Dashboard temps réel                     | ⚠         | ❌                        | ✅        | ✅                      | ✅               |
| Logs structurés (SQL)                    | ❌        | ❌                        | ⚠         | ✅                      | ✅               |
| Open-source                              | ✅        | ❌                        | ❌        | ✅                      | ✅               |
| Cible : utilisateur final                | ✅        | ✅                        | ✅        | ❌ (admin)              | ✅               |

## Détails par fonctionnalité

### 1. Blocage IP par listes

- Import direct des fichiers `.p2p` de **I-Blocklist** (compat PeerBlock).
- Support `.zip` automatique (format de distribution I-Blocklist).
- Support **CIDR** : FireHOL, Spamhaus DROP, listes custom.
- **Index fusionné** : plages adjacentes mergées pour réduire la mémoire.
- Activation/désactivation par liste sans relancer le moteur.

### 2. Règles de filtrage

- Modèle déclaratif type **pf/iptables** simplifié.
- Critères combinables : CIDR, port, port-range, protocole, direction, app.
- Actions : `ALLOW`, `BLOCK`, `LOG`, `ALERT`.
- Priorité numérique (0 = max).
- 4 règles utiles **par défaut** : block-telnet, block-smb-out, alert-rdp-in,
  block-bittorrent.

### 3. Deep Packet Inspection

10+ signatures L7 incluses :
- Web : HTTP, HTTP-Response, TLS-ClientHello, QUIC
- Remote : SSH, RDP
- P2P : BitTorrent (handshake + DHT)
- Filesharing : SMB
- Tunnel : Tor
- Infra : DNS
- Malware : signature générique C2

Permet de bloquer **BitTorrent sur port 443** (déguisé).

### 4. Filtrage applicatif

Politiques :
- **Blacklist** : "tout sauf X, Y, Z" (par défaut)
- **Whitelist** : "seulement X, Y, Z" (mode paranoia)

Resolution PID via psutil.net_connections() avec cache LRU.

Cas d'usage :
- Empêcher Chrome de contacter une plage IP
- Autoriser uniquement Firefox.exe et thunderbird.exe sur le port 443

### 5. IDS/IPS

Trois détecteurs en parallèle :

- **PortScanDetector** : vertical (>15 ports/cible/10s) + horizontal
  (>20 cibles/port/10s)
- **BruteForceDetector** : >10 tentatives/min sur ports sensibles
  (22, 21, 23, 25, 110, 143, 445, 3306, 3389, 5432, 5900)
- **FloodDetector** : >500 paquets/5s depuis la même source

Une alerte **critical** déclenche un **auto-ban** de 10 minutes (configurable).

### 6. Filtrage DNS

- Sinkhole : bloque la résolution avant que la connexion ne s'établisse.
- Compatible **format hosts** (StevenBlack, OISD).
- Wildcards automatiques : `foo.com` bloque `*.foo.com`.
- Catégories : ads-tracking, malware, phishing, parental, user, regex.
- Import depuis URL ou fichier local.

### 7. GeoIP

- Tables MaxMind GeoLite2 (CSV) ou table de démo.
- Mode **blacklist** : `blocked_countries = ["CN", "RU", "KP"]`
- Mode **whitelist** : `allowed_countries = ["FR", "BE", "CH"]` → tout le reste bloqué.

### 8. Threat Intelligence

Flux par défaut (désactivables individuellement) :
- **FireHOL Level1** — agrégat des pires IPs
- **Feodo Tracker** — botnets bancaires (Dridex, Emotet)
- **Tor exit nodes** — désactivé par défaut
- **Spamhaus DROP** — netblocs hijackés

Cache disque + TTL configurable par flux.

### 9. Interface graphique

- Thème sombre moderne (`#14151a` / `#4f46e5`).
- 5 vues : Dashboard, Journal, Règles, Listes, Paramètres.
- Dashboard : 8 cartes de métriques + graphe temps réel pyqtgraph.
- Journal : filtrage par verdict + recherche full-text.
- Notifications de status pour les alertes IDS.

### 10. Persistance

- **SQLite** pour les logs (index sur ts, verdict, dst_addr).
- **YAML** pour la config (`~/.nextgenblock/config.yaml`).
- **Cache TI** dans `~/.nextgenblock/ti/`.
