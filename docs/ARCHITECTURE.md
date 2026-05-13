# Architecture de NextGenBlock

## Philosophie

NextGenBlock applique les principes des **NGFW (Next-Generation Firewalls)**
commerciaux (Palo Alto, Fortinet, pfSense+Suricata) tout en gardant la
simplicité d'utilisation de PeerBlock.

Chaque paquet circule à travers une **chaîne de filtres** pluggables. Chaque
filtre peut émettre un verdict (`ALLOW`, `BLOCK`, `LOG`, `ALERT`) ou ne rien
dire (`None`) et laisser le suivant décider. Premier `BLOCK`/`ALERT` gagne.

## Vue d'ensemble

```
   Réseau (NIC) ←→  WinDivert (driver WFP)
                       │  raw packets
                       ▼
                ┌──────────────────┐
                │ FirewallEngine   │ thread "sniffer" + thread "processor"
                │  (file de pkts)  │
                └────────┬─────────┘
                         │ PacketEvent
        ┌────────────────┼────────────────────┐
        │   Chaîne de filtres (ordre fixé)    │
        │                                     │
        │  1. IDSEngine       (auto-ban)      │
        │  2. RuleEngine      (règles user)   │
        │  3. ThreatIntel     (réputation)    │
        │  4. BlocklistMgr    (CIDR)          │
        │  5. GeoIPFilter     (pays)          │
        │  6. DnsFilter       (sinkhole)      │
        │  7. AppFilter       (process)       │
        │  8. DPIEngine       (L7 sigs)       │
        └────────┬───────────────────┬────────┘
                 │ Verdict           │ Verdict
                 ▼                   ▼
            EventLogger          GUI (PyQt6)
            (SQLite)             signaux temps réel
```

## Couches principales

### 1. Capture (core/engine.py)

- **pydivert** (binding Python de WinDivert) lit les paquets en mode noyau via
  le **Windows Filtering Platform** (WFP).
- Producer-consumer : un thread sniffer dépose dans une `queue.Queue`,
  un thread processor déqueue, évalue et réinjecte si autorisé.
- Fail-open : si la file sature, on réinjecte directement (préfère perdre
  l'inspection plutôt que casser la connectivité).
- Mode `simulate=True` génère du trafic synthétique pour le développement.

### 2. Moteur de règles (core/rules.py)

- Modèle **pf/nftables** simplifié : priorité décroissante, premier match gagne.
- Critères : CIDR src/dst, port (unique ou range), protocole, direction,
  regex sur nom d'exécutable.
- Compilation à la création : `ipaddress.ip_network()` et `re.compile()` sont
  faits une seule fois.

### 3. Blocklists IP (core/blocklist.py)

- Compatible **format I-Blocklist .p2p** (héritage PeerBlock) ET **CIDR**.
- Stockage : intervalles `[start_int, end_int]` triés + index par `end_int`.
- Recherche : `bisect.bisect_left` en O(log n).
- Fusion automatique des plages adjacentes lors de la reconstruction.
- Téléchargement HTTP avec support des `.zip` (format I-Blocklist).

### 4. DPI (core/dpi.py)

- Signatures payload-based, **port-agnostiques** (détecte HTTP sur n'importe
  quel port).
- Catégories : web, p2p, voip, tunnel, remote, malware…
- Approche similaire à **nDPI** / **l7-filter**.

### 5. Filtrage applicatif (core/app_filter.py)

- Mapping 5-tuple → processus via **psutil.net_connections()**.
- Cache LRU (4096 entrées, TTL 5s) pour éviter le coût de l'énumération.
- Politiques : **blacklist** (par défaut) ou **whitelist stricte**.

### 6. IDS/IPS (core/ids.py)

- Compteurs **glissants** (deque + timestamps) — fenêtre paramétrable.
- Détecteurs : `PortScanDetector`, `BruteForceDetector`, `FloodDetector`.
- **Auto-ban** : une alerte critique bannit l'IP source pour N minutes
  (l'IP est ensuite refusée systématiquement, mécanisme similaire à fail2ban).

### 7. DNS Filter (core/dns_filter.py)

- Parse les QNAMEs des requêtes DNS (UDP/53).
- Index par suffixe : O(1) sur exact, O(profondeur) sur wildcard.
- Compatible **format hosts** (StevenBlack, OISD) et listes URL.

### 8. GeoIP (core/geoip.py)

- Recherche dichotomique sur plages triées.
- Source MaxMind GeoLite2 CSV (à brancher) + table de démo intégrée.
- Mode **blacklist** par pays ou **whitelist stricte**.

### 9. Threat Intelligence (core/threat_intel.py)

- Agrégateur de flux IoC : FireHOL, Feodo Tracker, Tor, Spamhaus.
- Score de confiance par flux → bloque seulement au-dessus du seuil.
- Cache disque + TTL par flux (24h par défaut).

### 10. GUI (gui/)

- **PyQt6** pour l'application principale + **pyqtgraph** pour les graphes.
- Thread principal Qt ↔ moteur via signaux Qt thread-safe.
- Dashboard rafraîchi toutes les secondes (lecture seule des compteurs).

### 11. Persistance (utils/logger.py + utils/config.py)

- **SQLite** pour les évènements (buffer write-behind toutes les 50 entrées).
- **YAML** (ou JSON fallback) pour la config utilisateur.

## Performance

| Aspect              | Mesure / cible |
|---------------------|----------------|
| Latence par paquet  | < 100 µs pour la chaîne entière (sans DPI) |
| Recherche blocklist | O(log n) ≈ 20 comparaisons pour 1M de plages |
| Recherche TI        | O(1) (dict sur IP exacte) |
| Mémoire             | ~ 60 MB pour 500k plages + 100k IoCs |
| Threads             | 2 (sniffer + processor) + Qt + IDS handlers |

## Extensibilité

Ajouter un nouveau filtre :

```python
def my_filter(evt: PacketEvent) -> Optional[Verdict]:
    if "evil" in evt.dst_addr:
        return Verdict.BLOCK
    return None

orchestrator.engine.add_filter("my-filter", my_filter)
```

C'est tout. Les filtres sont simplement des callables.

## Différences clés vs PeerBlock

1. **Driver moderne** : WinDivert (signé MS) au lieu de WinPkFilter abandonné.
2. **IPv6** natif.
3. **Multi-thread** : capture et traitement séparés, file tampon.
4. **Plus que de l'IP** : DPI, DNS, GeoIP, TI, IDS, app.
5. **Logs structurés** : SQLite avec index, queryable.
6. **Architecture modulaire** : chaque filtre est testable indépendamment.
