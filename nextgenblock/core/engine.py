"""
Moteur de capture et d'inspection de paquets.

Utilise WinDivert (via pydivert) — le standard de facto pour le filtrage de
paquets en mode noyau sur Windows moderne. WinDivert s'appuie sur le Windows
Filtering Platform (WFP), bien plus stable que les anciens hooks utilisés par
PeerBlock.

Architecture :
  - Thread principal "sniffer" : recv → évalue → send (ou drop) via le MÊME
    handle WinDivert. C'est obligatoire car le handle qui a reçu un paquet
    est le seul autorisé à le réinjecter dans la pile noyau.
  - Hooks observables (on_packet) appelés en async via une file pour ne pas
    bloquer la capture si la GUI ralentit.

Si pydivert n'est pas disponible (Linux ou Windows sans WinDivert),
on bascule automatiquement en mode "simulation" : trafic synthétique généré
pour démonstration et tests.
"""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class Verdict(Enum):
    """Décision finale prise pour un paquet."""
    ALLOW = "allow"
    BLOCK = "block"
    LOG = "log"      # autoriser mais logger (mode IDS)
    ALERT = "alert"  # bloquer + alerter l'utilisateur


@dataclass
class PacketEvent:
    """
    Représentation neutre d'un paquet, indépendante de pydivert.
    Permet de tester les modules de filtrage sans dépendance noyau.
    """
    src_addr: str
    dst_addr: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "TCP"          # TCP / UDP / ICMP
    direction: str = "outbound"    # inbound / outbound
    payload: bytes = b""
    timestamp: float = field(default_factory=time.time)
    interface_idx: int = 0
    pid: Optional[int] = None
    process_name: Optional[str] = None
    src_company: Optional[str] = None
    dst_company: Optional[str] = None
    src_country: Optional[str] = None
    dst_country: Optional[str] = None

    # Métadonnées remplies par les filtres
    matched_rule: Optional[str] = None
    threat_score: int = 0          # 0 = sain, 100 = malveillant
    tags: list[str] = field(default_factory=list)

    @property
    def remote_addr(self) -> str:
        return self.dst_addr if self.direction == "outbound" else self.src_addr

    @property
    def remote_port(self) -> int:
        return self.dst_port if self.direction == "outbound" else self.src_port


# Type d'un filtre : prend un paquet, renvoie un Verdict (ou None = pas d'avis)
FilterFn = Callable[[PacketEvent], Optional[Verdict]]


class FirewallEngine:
    """
    Orchestrateur central. Gère la capture, la chaîne de filtrage et la
    réinjection des paquets autorisés.
    """

    def __init__(self, simulate: bool = True, passive: bool = True) -> None:
        self.simulate = simulate
        self.passive = passive
        self._filters: list[tuple[str, FilterFn]] = []
        # File pour les hooks (observation seule). Si pleine, on perd
        # quelques évènements GUI mais la capture continue.
        self._hook_queue: queue.Queue = queue.Queue(maxsize=2000)
        self._running = threading.Event()
        self._threads: list[threading.Thread] = []

        # Hooks observables par la GUI
        self.on_packet: Optional[Callable[[PacketEvent, Verdict], None]] = None
        self.on_stats: Optional[Callable[[dict], None]] = None

        # Compteurs
        self.stats = {
            "total": 0,
            "allowed": 0,
            "blocked": 0,
            "logged": 0,
            "alerted": 0,
            "errors": 0,
            "dropped_hooks": 0,
        }
        self._stats_lock = threading.Lock()

    # ---- Configuration -------------------------------------------------

    def add_filter(self, name: str, fn: FilterFn) -> None:
        """Ajoute un filtre à la chaîne. L'ordre d'ajout = ordre d'évaluation."""
        self._filters.append((name, fn))

    def clear_filters(self) -> None:
        self._filters.clear()

    # ---- Cycle de vie --------------------------------------------------

    def start(self) -> None:
        if self._running.is_set():
            return
        self._running.set()

        sniffer = threading.Thread(target=self._sniff_loop, name="ngb-sniffer", daemon=True)
        hooks = threading.Thread(target=self._hook_loop, name="ngb-hooks", daemon=True)
        sniffer.start()
        hooks.start()
        self._threads = [sniffer, hooks]

    def stop(self) -> None:
        self._running.clear()
        for t in self._threads:
            t.join(timeout=2.0)
        self._threads.clear()

    # ---- Boucles internes ----------------------------------------------

    def _sniff_loop(self) -> None:
        """
        Capture + évaluation + réinjection dans un seul thread.
        Cette unicité est imposée par WinDivert : seul le handle ayant
        capté un paquet peut le réinjecter dans la pile noyau.
        """
        if self.simulate:
            self._simulated_traffic()
            return
        try:
            import pydivert  # noqa: WPS433
        except ImportError:
            print("[engine] pydivert indisponible — bascule en mode simulation.")
            self._simulated_traffic()
            return

        wd_filter = "ip or ipv6"
        try:
            flags = pydivert.Flag.SNIFF if self.passive else pydivert.Flag.DEFAULT
            with pydivert.WinDivert(wd_filter, flags=flags) as w:
                while self._running.is_set():
                    try:
                        raw = w.recv()
                    except Exception as e:
                        self._inc("errors")
                        print(f"[engine] recv error: {e}")
                        continue

                    evt = self._packet_to_event(raw)
                    verdict = self._evaluate(evt)

                    self._inc("total")
                    self._inc(self._counter_for(verdict))

                    # En mode passif/SNIFF, WinDivert copie les paquets sans
                    # les retenir : aucune reinjection, aucun blocage reseau.
                    if self.passive:
                        self._enqueue_hook(evt, verdict)
                        continue

                    # Réinjection si autorisé (ALLOW ou LOG)
                    if verdict in (Verdict.ALLOW, Verdict.LOG):
                        try:
                            w.send(raw)
                        except Exception as e:
                            self._inc("errors")
                            print(f"[engine] send error: {e}")

                    # Notifie les hooks de manière non-bloquante
                    self._enqueue_hook(evt, verdict)
        except Exception as e:
            print(f"[engine] WinDivert non disponible: {e}")
            self._simulated_traffic()

    def _packet_to_event(self, raw) -> PacketEvent:
        """Convertit un paquet pydivert en PacketEvent neutre."""
        direction = "inbound" if raw.is_inbound else "outbound"
        if raw.tcp:
            proto = "TCP"
        elif raw.udp:
            proto = "UDP"
        elif raw.icmpv4 or raw.icmpv6:
            proto = "ICMP"
        else:
            proto = "OTHER"
        src_port = (raw.src_port or 0) if (raw.tcp or raw.udp) else 0
        dst_port = (raw.dst_port or 0) if (raw.tcp or raw.udp) else 0
        payload = bytes(raw.payload) if raw.payload else b""

        return PacketEvent(
            src_addr=str(raw.src_addr),
            dst_addr=str(raw.dst_addr),
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            direction=direction,
            payload=payload,
            interface_idx=raw.interface[0] if raw.interface else 0,
        )

    def _hook_loop(self) -> None:
        """
        Consomme les évènements de la file et appelle les callbacks
        (logger, GUI). Séparé du sniffer pour ne jamais bloquer la capture.
        """
        while self._running.is_set():
            try:
                evt, verdict = self._hook_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if self.on_packet:
                try:
                    self.on_packet(evt, verdict)
                except Exception as e:
                    print(f"[engine] on_packet hook error: {e}")

    def _enqueue_hook(self, evt: PacketEvent, verdict: Verdict) -> None:
        try:
            self._hook_queue.put_nowait((evt, verdict))
        except queue.Full:
            self._inc("dropped_hooks")

    def _evaluate(self, evt: PacketEvent) -> Verdict:
        """
        Chaîne de filtres :
          * BLOCK / ALERT → arrêt immédiat
          * LOG → continue mais retient le verdict si rien de plus grave après
          * None → ignoré, on continue
        À la fin sans match : ALLOW.
        """
        soft_verdict: Optional[Verdict] = None
        for name, fn in self._filters:
            try:
                v = fn(evt)
            except Exception as e:
                print(f"[engine] filter {name} error: {e}")
                self._inc("errors")
                continue
            if v is None:
                continue
            if v in (Verdict.BLOCK, Verdict.ALERT):
                if evt.matched_rule is None:
                    evt.matched_rule = name
                return v
            if v == Verdict.LOG:
                if soft_verdict is None:
                    if evt.matched_rule is None:
                        evt.matched_rule = name
                    soft_verdict = Verdict.LOG
            elif v == Verdict.ALLOW:
                # ALLOW explicite : on respecte mais on continue à observer
                # les blocages ultérieurs (politique sécurité priorité au pire)
                soft_verdict = Verdict.ALLOW
        return soft_verdict or Verdict.ALLOW

    # ---- Helpers -------------------------------------------------------

    def _counter_for(self, v: Verdict) -> str:
        return {
            Verdict.ALLOW: "allowed",
            Verdict.BLOCK: "blocked",
            Verdict.LOG: "logged",
            Verdict.ALERT: "alerted",
        }[v]

    def _inc(self, key: str, n: int = 1) -> None:
        with self._stats_lock:
            self.stats[key] = self.stats.get(key, 0) + n

    def get_stats(self) -> dict:
        with self._stats_lock:
            return dict(self.stats)

    # ---- Mode simulation (sans WinDivert) ------------------------------

    def _simulated_traffic(self) -> None:
        """Génère du trafic synthétique pour la démo/tests."""
        import random
        samples_out = [
            ("203.0.113.45", 443, "TCP"),
            ("8.8.8.8", 53, "UDP"),
            ("198.51.100.7", 80, "TCP"),
            ("185.199.108.153", 443, "TCP"),
            ("1.2.3.4", 6881, "TCP"),  # BitTorrent (bloqué par démo blocklist)
            ("91.189.91.157", 80, "TCP"),
            ("5.135.10.20", 22, "TCP"),  # SSH dans plage "RU" démo
            ("192.0.2.10", 23, "TCP"),   # Telnet (bloqué par règle par défaut)
        ]
        local = "192.168.1.42"
        while self._running.is_set():
            dst, port, proto = random.choice(samples_out)
            evt = PacketEvent(
                src_addr=local,
                dst_addr=dst,
                src_port=random.randint(40000, 60000),
                dst_port=port,
                protocol=proto,
                direction="outbound",
                payload=b"GET / HTTP/1.1\r\nHost: test\r\n\r\n" if port == 80 else b"",
            )
            verdict = self._evaluate(evt)
            self._inc("total")
            self._inc(self._counter_for(verdict))
            self._enqueue_hook(evt, verdict)
            time.sleep(random.uniform(0.05, 0.4))
