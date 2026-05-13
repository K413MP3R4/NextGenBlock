"""
Filtrage GeoIP — bloque par pays d'origine/destination.

Idéalement on utilise la base MaxMind GeoLite2. Pour rester sans dépendance
binaire, on fournit ici une implémentation pluggable qui :

  * accepte un fichier CSV "start_ip,end_ip,country" (format MaxMind CSV),
  * ou utilise une mini-table embarquée pour démo,
  * recherche dichotomique par bornes triées.

Pour la production : pip install geoip2 + GeoLite2-Country.mmdb.
"""
from __future__ import annotations

import bisect
import ipaddress
import threading
from typing import Optional

from .engine import PacketEvent, Verdict


# Mini-table embarquée pour démo (très partielle, à remplacer par MaxMind)
_DEMO_RANGES = [
    # (start_int, end_int, "ISO")
    (int(ipaddress.ip_address("1.0.0.0")),     int(ipaddress.ip_address("1.255.255.255")),     "AU"),
    (int(ipaddress.ip_address("2.0.0.0")),     int(ipaddress.ip_address("2.255.255.255")),     "FR"),
    (int(ipaddress.ip_address("8.8.8.0")),     int(ipaddress.ip_address("8.8.8.255")),         "US"),
    (int(ipaddress.ip_address("185.0.0.0")),   int(ipaddress.ip_address("185.255.255.255")),   "EU"),
    (int(ipaddress.ip_address("203.0.113.0")), int(ipaddress.ip_address("203.0.113.255")),     "JP"),
    (int(ipaddress.ip_address("198.51.100.0")),int(ipaddress.ip_address("198.51.100.255")),    "CA"),
    (int(ipaddress.ip_address("91.0.0.0")),    int(ipaddress.ip_address("91.255.255.255")),    "EU"),
    (int(ipaddress.ip_address("5.0.0.0")),     int(ipaddress.ip_address("5.255.255.255")),     "RU"),
    (int(ipaddress.ip_address("116.0.0.0")),   int(ipaddress.ip_address("116.255.255.255")),   "CN"),
]


class GeoIPFilter:
    """
    Politique :
      * blacklist : bloquer les pays de `blocked_countries`
      * whitelist : si `allowed_countries` non vide, bloquer tout pays non listé
    """

    def __init__(self) -> None:
        self.blocked_countries: set[str] = set()
        self.allowed_countries: set[str] = set()
        self._starts: list[int] = []
        self._ends: list[int] = []
        self._codes: list[str] = []
        self._lock = threading.RLock()
        self.load_ranges(_DEMO_RANGES)
        self.stats: dict[str, int] = {}

    def load_ranges(self, ranges: list[tuple[int, int, str]]) -> None:
        with self._lock:
            ranges = sorted(ranges, key=lambda r: r[0])
            self._starts = [r[0] for r in ranges]
            self._ends = [r[1] for r in ranges]
            self._codes = [r[2] for r in ranges]

    def load_csv(self, path: str) -> int:
        """Charge un CSV : start_ip,end_ip,country_iso."""
        import csv
        ranges: list[tuple[int, int, str]] = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 3:
                    continue
                try:
                    s = int(ipaddress.ip_address(row[0].strip()))
                    e = int(ipaddress.ip_address(row[1].strip()))
                    c = row[2].strip().upper()
                    ranges.append((s, e, c))
                except ValueError:
                    continue
        self.load_ranges(ranges)
        return len(ranges)

    def country_of(self, ip: str) -> Optional[str]:
        try:
            n = int(ipaddress.ip_address(ip))
        except ValueError:
            return None
        with self._lock:
            idx = bisect.bisect_left(self._ends, n)
            if idx >= len(self._ends):
                return None
            if self._starts[idx] <= n <= self._ends[idx]:
                return self._codes[idx]
        return None

    def block(self, country_iso: str) -> None:
        self.blocked_countries.add(country_iso.upper())

    def allow_only(self, country_iso: str) -> None:
        self.allowed_countries.add(country_iso.upper())

    def __call__(self, evt: PacketEvent) -> Optional[Verdict]:
        code = self.country_of(evt.remote_addr)
        if not code:
            return None
        self.stats[code] = self.stats.get(code, 0) + 1
        evt.tags.append(f"geo:{code}")
        if code in self.blocked_countries:
            evt.threat_score = max(evt.threat_score, 40)
            return Verdict.BLOCK
        if self.allowed_countries and code not in self.allowed_countries:
            evt.threat_score = max(evt.threat_score, 40)
            return Verdict.BLOCK
        return None
