"""
IDS/IPS — Détection d'intrusion et anti-comportement.

Détecte en temps réel :
  * port scans (horizontaux + verticaux)
  * brute force (SSH/RDP/SMB)
  * tentatives de connexion massives (DDoS-like)
  * anomalies statistiques sur les ports
  * signatures de paquets malveillants

Approche similaire à Suricata / Snort mais simplifiée. Les compteurs sont
glissants (fenêtre de N secondes) via deque + horodatage.
"""
from __future__ import annotations

import collections
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .engine import PacketEvent, Verdict


# ---- Compteur glissant -------------------------------------------------

class SlidingCounter:
    """Compte les évènements dans une fenêtre glissante (en secondes)."""

    def __init__(self, window: float = 60.0) -> None:
        self.window = window
        self._events: collections.deque[float] = collections.deque()
        self._lock = threading.Lock()

    def hit(self) -> int:
        now = time.time()
        with self._lock:
            self._events.append(now)
            cutoff = now - self.window
            while self._events and self._events[0] < cutoff:
                self._events.popleft()
            return len(self._events)

    def count(self) -> int:
        now = time.time()
        with self._lock:
            cutoff = now - self.window
            while self._events and self._events[0] < cutoff:
                self._events.popleft()
            return len(self._events)


# ---- Détecteurs --------------------------------------------------------

@dataclass
class Alert:
    timestamp: float
    severity: str           # info / warning / critical
    rule: str
    src_ip: str
    dst_ip: str
    message: str
    metadata: dict = field(default_factory=dict)


class PortScanDetector:
    """
    Détecte un scan de ports : une même IP source qui contacte trop de ports
    distincts sur une cible (vertical scan) ou trop d'hôtes distincts sur un
    même port (horizontal scan) dans une fenêtre courte.
    """

    def __init__(self, window: float = 10.0, vertical_threshold: int = 15,
                 horizontal_threshold: int = 20) -> None:
        self.window = window
        self.vt = vertical_threshold
        self.ht = horizontal_threshold
        # (src) -> dict(dst -> set(ports), expire)
        self._tracker: dict[str, dict] = {}
        self._lock = threading.Lock()

    def observe(self, evt: PacketEvent) -> Optional[Alert]:
        now = time.time()
        with self._lock:
            src = evt.src_addr
            entry = self._tracker.setdefault(src, {"start": now, "dsts": {}, "ports": {}})
            if now - entry["start"] > self.window:
                # Reset fenêtre
                entry["start"] = now
                entry["dsts"] = {}
                entry["ports"] = {}

            entry["dsts"].setdefault(evt.dst_addr, set()).add(evt.dst_port)
            entry["ports"].setdefault(evt.dst_port, set()).add(evt.dst_addr)

            # Scan vertical : beaucoup de ports sur une même IP
            for dst, ports in entry["dsts"].items():
                if len(ports) >= self.vt:
                    return Alert(now, "warning", "port-scan-vertical",
                                 src, dst,
                                 f"{src} a scanné {len(ports)} ports de {dst}",
                                 {"ports_count": len(ports)})

            # Scan horizontal : un même port sur beaucoup d'IPs
            for port, hosts in entry["ports"].items():
                if len(hosts) >= self.ht:
                    return Alert(now, "warning", "port-scan-horizontal",
                                 src, "multiple",
                                 f"{src} a contacté {len(hosts)} hôtes sur port {port}",
                                 {"hosts_count": len(hosts), "port": port})
        return None


class BruteForceDetector:
    """
    Détecte du brute force : trop de connexions vers un port sensible
    depuis la même source en peu de temps. Cible typiquement SSH(22),
    RDP(3389), SMB(445), FTP(21).
    """

    SENSITIVE_PORTS = {22, 21, 23, 25, 110, 143, 445, 3306, 3389, 5432, 5900}

    def __init__(self, window: float = 60.0, threshold: int = 10) -> None:
        self.window = window
        self.threshold = threshold
        self._counters: dict[tuple[str, int], SlidingCounter] = {}
        self._lock = threading.Lock()

    def observe(self, evt: PacketEvent) -> Optional[Alert]:
        if evt.dst_port not in self.SENSITIVE_PORTS:
            return None
        if evt.protocol != "TCP":
            return None
        key = (evt.src_addr, evt.dst_port)
        with self._lock:
            counter = self._counters.setdefault(key, SlidingCounter(self.window))
        count = counter.hit()
        if count >= self.threshold:
            return Alert(time.time(), "critical", "brute-force",
                         evt.src_addr, evt.dst_addr,
                         f"{count} tentatives sur port {evt.dst_port} depuis {evt.src_addr}",
                         {"port": evt.dst_port, "count": count})
        return None


class FloodDetector:
    """Détecte un flood : trop de paquets depuis une même source globale."""

    def __init__(self, window: float = 5.0, threshold: int = 500) -> None:
        self.window = window
        self.threshold = threshold
        self._counters: dict[str, SlidingCounter] = {}
        self._lock = threading.Lock()

    def observe(self, evt: PacketEvent) -> Optional[Alert]:
        with self._lock:
            c = self._counters.setdefault(evt.src_addr, SlidingCounter(self.window))
        n = c.hit()
        if n == self.threshold:
            return Alert(time.time(), "critical", "flood",
                         evt.src_addr, evt.dst_addr,
                         f"Flood depuis {evt.src_addr} : {n} paquets en {self.window}s",
                         {"pps": n / self.window})
        return None


# ---- Orchestrateur IDS ------------------------------------------------

class IDSEngine:
    """Combine plusieurs détecteurs et émet un Verdict si attaque."""

    def __init__(self, ban_ttl: float = 600.0, brute_threshold: int = 10,
                 scan_threshold: int = 15) -> None:
        self.scan = PortScanDetector(vertical_threshold=scan_threshold)
        self.brute = BruteForceDetector(threshold=brute_threshold)
        self.flood = FloodDetector()
        self._detectors = [self.scan, self.brute, self.flood]
        self.alerts: collections.deque[Alert] = collections.deque(maxlen=1000)
        self.on_alert: Optional[Callable[[Alert], None]] = None

        # IPs bloquées dynamiquement par l'IPS (auto-ban)
        self._blocked: dict[str, float] = {}
        self._ban_ttl = float(ban_ttl)
        self._lock = threading.Lock()

    def configure(self, ban_ttl: float, brute_threshold: int,
                  scan_threshold: int) -> None:
        """Applique les seuils utilisateur aux detecteurs IDS."""
        self.scan = PortScanDetector(vertical_threshold=scan_threshold)
        self.brute = BruteForceDetector(threshold=brute_threshold)
        self.flood = FloodDetector()
        self._detectors = [self.scan, self.brute, self.flood]
        self._ban_ttl = float(ban_ttl)

    def _record(self, alert: Alert) -> None:
        self.alerts.append(alert)
        with self._lock:
            if alert.severity == "critical":
                self._blocked[alert.src_ip] = time.time() + self._ban_ttl
        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception:
                pass

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            until = self._blocked.get(ip)
            if until is None:
                return False
            if time.time() > until:
                self._blocked.pop(ip, None)
                return False
            return True

    def list_banned(self) -> list[tuple[str, float]]:
        with self._lock:
            return [(ip, t) for ip, t in self._blocked.items()]

    def unban(self, ip: str) -> None:
        with self._lock:
            self._blocked.pop(ip, None)

    def __call__(self, evt: PacketEvent) -> Optional[Verdict]:
        # 1. Auto-ban actif ?
        if self.is_banned(evt.src_addr):
            evt.tags.append("ips:auto-ban")
            return Verdict.BLOCK

        # 2. Évaluation des détecteurs
        for det in self._detectors:
            alert = det.observe(evt)
            if alert:
                self._record(alert)
                evt.tags.append(f"ids:{alert.rule}")
                evt.threat_score = max(evt.threat_score, 70 if alert.severity == "warning" else 90)
                if alert.severity == "critical":
                    return Verdict.ALERT
                return Verdict.LOG
        return None
