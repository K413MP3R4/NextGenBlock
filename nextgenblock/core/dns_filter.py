"""
Filtrage DNS — sinkhole et résolution sécurisée.

Inspecte les requêtes DNS (UDP/53) sortantes et bloque les domaines listés.
Approche identique à Pi-hole / NextDNS / AdGuard Home.

Sources recommandées :
  * StevenBlack/hosts (malware + ads + porn + fakenews)
  * URLhaus
  * OISD
  * Disconnect.me trackers

Wildcards : un domaine "foo.com" bloque foo.com et *.foo.com.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Optional

from .engine import PacketEvent, Verdict


@dataclass
class DnsBlockEntry:
    domain: str
    category: str = "generic"   # ads / malware / tracking / phishing
    source: str = ""


class DnsFilter:
    """
    Maintient un ensemble de domaines bloqués + une recherche par suffixe O(1)
    via dict des labels inversés.
    """

    def __init__(self) -> None:
        self._exact: set[str] = set()
        self._suffix: set[str] = set()         # bloque *.example.com
        self._entries: dict[str, DnsBlockEntry] = {}
        self._regex: list[re.Pattern] = []
        self._lock = threading.RLock()
        self.stats = {"queries": 0, "blocked": 0}

    def add(self, domain: str, category: str = "generic", source: str = "",
            wildcard: bool = True) -> None:
        d = domain.lower().strip(".")
        if not d:
            return
        with self._lock:
            entry = DnsBlockEntry(d, category, source)
            self._entries[d] = entry
            self._exact.add(d)
            if wildcard:
                self._suffix.add(d)

    def add_regex(self, pattern: str) -> None:
        self._regex.append(re.compile(pattern, re.IGNORECASE))

    def remove(self, domain: str) -> None:
        d = domain.lower().strip(".")
        with self._lock:
            self._exact.discard(d)
            self._suffix.discard(d)
            self._entries.pop(d, None)

    def is_blocked(self, qname: str) -> Optional[DnsBlockEntry]:
        d = qname.lower().rstrip(".")
        with self._lock:
            if d in self._exact:
                return self._entries.get(d)
            # Vérifier les suffixes (wildcards)
            parts = d.split(".")
            for i in range(len(parts)):
                cand = ".".join(parts[i:])
                if cand in self._suffix:
                    return self._entries.get(cand)
            for r in self._regex:
                if r.search(d):
                    return DnsBlockEntry(d, "regex", "regex")
        return None

    # ---- Implémente FilterFn -----------------------------------------

    def __call__(self, evt: PacketEvent) -> Optional[Verdict]:
        # On ne traite que les requêtes DNS
        if evt.protocol != "UDP" or (evt.remote_port != 53 and evt.dst_port != 53):
            return None
        if not evt.payload or len(evt.payload) < 13:
            return None

        self.stats["queries"] += 1
        qname = _parse_dns_qname(evt.payload)
        if not qname:
            return None

        evt.tags.append(f"dns:{qname[:60]}")
        entry = self.is_blocked(qname)
        if entry:
            self.stats["blocked"] += 1
            evt.tags.append(f"dns-block:{entry.category}")
            evt.threat_score = max(evt.threat_score, 50)
            return Verdict.BLOCK
        return None

    def total(self) -> int:
        with self._lock:
            return len(self._exact)

    # ---- Chargement de listes hosts ----------------------------------

    def load_hosts_file(self, text: str, category: str = "ads",
                        source: str = "") -> int:
        """Charge un fichier au format hosts (0.0.0.0 domain.com)."""
        n = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::"):
                self.add(parts[1], category=category, source=source)
                n += 1
            elif len(parts) == 1 and "." in parts[0]:
                self.add(parts[0], category=category, source=source)
                n += 1
        return n


def _parse_dns_qname(payload: bytes) -> Optional[str]:
    """Extrait le QNAME d'une requête DNS (offset 12)."""
    try:
        i = 12
        labels: list[str] = []
        while i < len(payload):
            ln = payload[i]
            if ln == 0:
                break
            if ln & 0xC0:
                return None  # Compression — improbable en requête
            i += 1
            labels.append(payload[i:i + ln].decode("ascii", errors="ignore"))
            i += ln
        return ".".join(labels) if labels else None
    except Exception:
        return None
