"""
Threat Intelligence — agrégateur de flux IoC (Indicators of Compromise).

Récupère et fusionne des flux d'IPs malveillantes connues depuis plusieurs
sources gratuites. Chaque IoC contient un score de confiance et une catégorie
(C2, brute-force, scanner, tor-exit, etc.).

Sources publiques utilisables (configurées par défaut, désactivées) :

  * AbuseIPDB (clé API requise) — réputation crowd-sourcée
  * URLhaus (abuse.ch) — domaines/IPs distribuant du malware
  * Feodo Tracker (abuse.ch) — botnets bancaires
  * Tor exit nodes (officiel)
  * FireHOL level1
  * Spamhaus DROP / EDROP
  * Emerging Threats compromised IPs

Pour l'éthique et la perf : on cache localement, on respecte les TTL,
on ne fait pas de requête par paquet.
"""
from __future__ import annotations

import bisect
import ipaddress
import json
import os
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from .engine import PacketEvent, Verdict


@dataclass
class IoCEntry:
    ip: str
    category: str         # c2, malware, scanner, tor, spam, brute
    confidence: int       # 0-100
    source: str
    first_seen: float = field(default_factory=time.time)


@dataclass
class ThreatFeed:
    name: str
    url: str
    fmt: str = "plain"    # plain | json-abuseipdb | csv
    category: str = "generic"
    confidence: int = 70
    enabled: bool = True
    last_updated: float = 0.0
    refresh_seconds: int = 24 * 3600


DEFAULT_FEEDS: list[ThreatFeed] = [
    ThreatFeed("FireHOL-level1",
               "https://iplists.firehol.org/files/firehol_level1.netset",
               fmt="plain", category="firehol", confidence=80),
    ThreatFeed("Feodo-Tracker",
               "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
               fmt="plain", category="c2", confidence=95),
    ThreatFeed("Tor-Exit",
               "https://check.torproject.org/torbulkexitlist",
               fmt="plain", category="tor", confidence=50, enabled=False),
    ThreatFeed("Spamhaus-DROP",
               "https://www.spamhaus.org/drop/drop.txt",
               fmt="plain", category="spam", confidence=90),
]


class ThreatIntel:
    """Index global d'IoCs avec recherche O(1) par IP."""

    def __init__(self, cache_dir: Optional[str] = None) -> None:
        self._iocs: dict[str, IoCEntry] = {}
        self._net_starts: list[int] = []
        self._net_ends: list[int] = []
        self._net_iocs: list[IoCEntry] = []
        self._feeds: dict[str, ThreatFeed] = {f.name: f for f in DEFAULT_FEEDS}
        self._lock = threading.RLock()
        self.cache_dir = cache_dir or os.path.join(
            os.path.expanduser("~"), ".nextgenblock", "ti"
        )
        os.makedirs(self.cache_dir, exist_ok=True)
        self.min_confidence = 70  # Score minimum pour bloquer
        self.stats = {"hits": 0, "iocs": 0}

    # ---- Gestion des flux --------------------------------------------

    def add_feed(self, feed: ThreatFeed) -> None:
        with self._lock:
            self._feeds[feed.name] = feed

    def list_feeds(self) -> list[ThreatFeed]:
        with self._lock:
            return list(self._feeds.values())

    def add_ioc(self, ioc: IoCEntry) -> None:
        if "/" in ioc.ip:
            self.add_network(ioc)
            return
        with self._lock:
            existing = self._iocs.get(ioc.ip)
            if existing is None or ioc.confidence > existing.confidence:
                self._iocs[ioc.ip] = ioc

    def add_network(self, ioc: IoCEntry) -> None:
        """Ajoute un IoC reseau sans expanser toutes les adresses."""
        try:
            net = ipaddress.ip_network(ioc.ip, strict=False)
        except ValueError:
            return
        if net.num_addresses == 1:
            self.add_ioc(IoCEntry(
                str(net.network_address), ioc.category, ioc.confidence,
                ioc.source, ioc.first_seen
            ))
            return
        start = int(net.network_address)
        end = int(net.broadcast_address)
        with self._lock:
            idx = bisect.bisect_left(self._net_starts, start)
            self._net_starts.insert(idx, start)
            self._net_ends.insert(idx, end)
            self._net_iocs.insert(idx, ioc)

    def refresh(self, force: bool = False) -> dict[str, int]:
        """Rafraîchit tous les flux activés. Retourne {feed: nb_ioc}."""
        results = {}
        for feed in list(self._feeds.values()):
            if not feed.enabled:
                continue
            if not force and (time.time() - feed.last_updated) < feed.refresh_seconds:
                continue
            try:
                n = self._fetch_feed(feed)
                feed.last_updated = time.time()
                results[feed.name] = n
            except Exception as e:
                print(f"[TI] échec {feed.name}: {e}")
                results[feed.name] = 0
        with self._lock:
            self.stats["iocs"] = self.total_iocs()
        return results

    def _fetch_feed(self, feed: ThreatFeed) -> int:
        cache_path = os.path.join(self.cache_dir, feed.name + ".txt")
        try:
            req = urllib.request.Request(
                feed.url, headers={"User-Agent": "NextGenBlock/1.0"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read().decode("utf-8", errors="ignore")
            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(data)
        except Exception:
            if not os.path.exists(cache_path):
                raise
            with open(cache_path, "r", encoding="utf-8") as f:
                data = f.read()

        n = 0
        for ip in _parse_plain_feed(data):
            self.add_ioc(IoCEntry(ip, feed.category, feed.confidence, feed.name))
            n += 1
        return n

    # ---- Lookup ------------------------------------------------------

    def lookup(self, ip: str) -> Optional[IoCEntry]:
        with self._lock:
            exact = self._iocs.get(ip)
            if exact is not None:
                return exact
            try:
                n = int(ipaddress.ip_address(ip))
            except ValueError:
                return None
            idx = bisect.bisect_right(self._net_starts, n) - 1
            best: Optional[IoCEntry] = None
            while idx >= 0 and self._net_starts[idx] <= n:
                if n <= self._net_ends[idx]:
                    cand = self._net_iocs[idx]
                    if best is None or cand.confidence > best.confidence:
                        best = cand
                idx -= 1
            if best is not None:
                return best
            return None

    def __call__(self, evt: PacketEvent) -> Optional[Verdict]:
        ioc = self.lookup(evt.remote_addr)
        if ioc is None:
            return None
        self.stats["hits"] = self.stats.get("hits", 0) + 1
        evt.tags.append(f"ti:{ioc.category}")
        evt.threat_score = max(evt.threat_score, ioc.confidence)
        if ioc.confidence >= self.min_confidence:
            return Verdict.BLOCK
        return Verdict.LOG

    def total_iocs(self) -> int:
        with self._lock:
            return len(self._iocs) + len(self._net_iocs)


def _parse_plain_feed(text: str):
    """Parse un flux texte (une IP ou CIDR par ligne)."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        token = line.split()[0]
        try:
            net = ipaddress.ip_network(token, strict=False)
            if net.num_addresses == 1:
                yield str(net.network_address)
            elif net.num_addresses:
                yield str(net)
            else:
                # Pour les CIDR, on n'expanse pas (potentiellement énorme)
                # On stocke uniquement les /24 et plus petits
                if net.num_addresses <= 256:
                    for ip in net.hosts():
                        yield str(ip)
        except ValueError:
            continue
