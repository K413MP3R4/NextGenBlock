"""
Gestionnaire de listes de blocage IP.

Compatible avec les formats historiques de PeerBlock :
  * P2P (start_ip - end_ip : description)        — format I-Blocklist .p2p
  * CIDR (a.b.c.d/n)                              — format moderne

Optimisé pour des millions de plages : utilise un arbre d'intervalles
trié + recherche dichotomique en O(log n).

Sources recommandées (URLs à configurer) :
  - I-Blocklist (level1, ads, spyware, badpeers)
  - Spamhaus DROP / EDROP
  - Emerging Threats compromised IPs
  - FireHOL level1-4
"""
from __future__ import annotations

import bisect
import ipaddress
import os
import threading
import urllib.request
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from typing import Optional

from .engine import PacketEvent, Verdict


@dataclass
class IPRange:
    start: int
    end: int
    label: str = ""
    source: str = ""


@dataclass
class Blocklist:
    name: str
    enabled: bool = True
    ranges: list[IPRange] = field(default_factory=list)
    source_url: Optional[str] = None
    last_updated: float = 0.0

    @property
    def size(self) -> int:
        return len(self.ranges)


class BlocklistManager:
    """
    Conteneur de plusieurs listes. Recherche fusionnée optimisée.

    Stratégie :
      * Toutes les plages activées sont fusionnées dans un tableau trié.
      * `is_blocked()` fait une recherche dichotomique sur les bornes de fin.
      * Le tableau est régénéré uniquement quand on ajoute/supprime une liste.
    """

    def __init__(self) -> None:
        self._lists: dict[str, Blocklist] = {}
        self._sorted_starts: list[int] = []
        self._sorted_ends: list[int] = []
        self._sorted_labels: list[str] = []
        self._lock = threading.RLock()

    # ---- Gestion des listes -------------------------------------------

    def add_list(self, bl: Blocklist) -> None:
        with self._lock:
            self._lists[bl.name] = bl
            self._rebuild_index()

    def remove_list(self, name: str) -> None:
        with self._lock:
            self._lists.pop(name, None)
            self._rebuild_index()

    def toggle(self, name: str, enabled: bool) -> None:
        with self._lock:
            if name in self._lists:
                self._lists[name].enabled = enabled
                self._rebuild_index()

    def lists(self) -> list[Blocklist]:
        with self._lock:
            return list(self._lists.values())

    def _rebuild_index(self) -> None:
        merged: list[IPRange] = []
        for bl in self._lists.values():
            if bl.enabled:
                merged.extend(bl.ranges)
        merged.sort(key=lambda r: r.start)
        # Fusion des plages adjacentes pour réduire la taille
        compact: list[IPRange] = []
        for r in merged:
            if compact and r.start <= compact[-1].end + 1:
                if r.end > compact[-1].end:
                    compact[-1].end = r.end
                    compact[-1].label += f"; {r.label}"
            else:
                compact.append(IPRange(r.start, r.end, r.label, r.source))
        self._sorted_starts = [r.start for r in compact]
        self._sorted_ends = [r.end for r in compact]
        self._sorted_labels = [r.label for r in compact]

    # ---- Recherche ----------------------------------------------------

    def is_blocked(self, ip: str) -> Optional[str]:
        """Retourne le label de la plage qui matche, sinon None."""
        try:
            n = int(ipaddress.ip_address(ip))
        except ValueError:
            return None
        with self._lock:
            # Trouver la plage candidate : première end >= n
            idx = bisect.bisect_left(self._sorted_ends, n)
            if idx >= len(self._sorted_ends):
                return None
            if self._sorted_starts[idx] <= n <= self._sorted_ends[idx]:
                return self._sorted_labels[idx]
        return None

    # ---- Implémente FilterFn pour l'Engine ---------------------------

    def __call__(self, evt: PacketEvent) -> Optional[Verdict]:
        # On vérifie l'IP distante (la moins fiable des deux)
        label = self.is_blocked(evt.remote_addr)
        if label:
            evt.tags.append(f"blocklist:{label[:40]}")
            evt.threat_score = max(evt.threat_score, 60)
            return Verdict.BLOCK
        return None

    # ---- Parseurs de formats -----------------------------------------

    @staticmethod
    def parse_p2p_format(data: str, source: str = "") -> list[IPRange]:
        """
        Format I-Blocklist .p2p :
            Description:start_ip-end_ip
        """
        ranges: list[IPRange] = []
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                label, addrs = line.rsplit(":", 1)
                start_s, end_s = addrs.split("-")
                start = int(ipaddress.ip_address(start_s.strip()))
                end = int(ipaddress.ip_address(end_s.strip()))
                if end < start:
                    start, end = end, start
                ranges.append(IPRange(start, end, label.strip(), source))
            except Exception:
                continue
        return ranges

    @staticmethod
    def parse_cidr_format(data: str, source: str = "") -> list[IPRange]:
        """Une ligne = un CIDR ou une IP."""
        ranges: list[IPRange] = []
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            # Retirer commentaire en fin de ligne
            token = line.split()[0].split(";")[0]
            try:
                net = ipaddress.ip_network(token, strict=False)
                ranges.append(IPRange(int(net.network_address),
                                      int(net.broadcast_address),
                                      label=line[len(token):].strip() or token,
                                      source=source))
            except ValueError:
                # Peut-être un range "a-b" ?
                if "-" in token:
                    try:
                        a, b = token.split("-")
                        ranges.append(IPRange(
                            int(ipaddress.ip_address(a.strip())),
                            int(ipaddress.ip_address(b.strip())),
                            source=source,
                        ))
                    except Exception:
                        pass
        return ranges

    # ---- Téléchargement ----------------------------------------------

    def download_list(self, name: str, url: str, fmt: str = "auto",
                      timeout: int = 30) -> Blocklist:
        """
        Télécharge une liste depuis une URL. `fmt` : 'p2p' | 'cidr' | 'auto'.
        Supporte les archives .zip de I-Blocklist.
        """
        req = urllib.request.Request(
            url, headers={"User-Agent": "NextGenBlock/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()

        # Décompresser si .zip
        text: str
        if url.lower().endswith(".zip") or raw[:2] == b"PK":
            with zipfile.ZipFile(BytesIO(raw)) as z:
                first = z.namelist()[0]
                text = z.read(first).decode("utf-8", errors="ignore")
        else:
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("latin-1", errors="ignore")

        if fmt == "auto":
            fmt = "p2p" if ":" in text.splitlines()[0] and "-" in text else "cidr"

        if fmt == "p2p":
            ranges = self.parse_p2p_format(text, source=url)
        else:
            ranges = self.parse_cidr_format(text, source=url)

        import time as _t
        bl = Blocklist(name=name, ranges=ranges, source_url=url, last_updated=_t.time())
        self.add_list(bl)
        return bl

    # ---- Persistance --------------------------------------------------

    def total_ranges(self) -> int:
        with self._lock:
            return len(self._sorted_starts)


def builtin_demo_list() -> Blocklist:
    """Liste de démonstration avec quelques plages connues pour test."""
    rngs = [
        IPRange(int(ipaddress.ip_address("1.2.3.0")),
                int(ipaddress.ip_address("1.2.3.255")),
                "Demo P2P monitor 1", "builtin"),
        IPRange(int(ipaddress.ip_address("5.0.0.0")),
                int(ipaddress.ip_address("5.255.255.255")),
                "Demo bad ASN", "builtin"),
    ]
    return Blocklist(name="demo-builtin", ranges=rngs)
