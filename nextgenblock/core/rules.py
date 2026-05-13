"""
Moteur de règles déclaratives.

Une règle décrit : QUI (CIDR / port / protocole / direction / app) et
QUE FAIRE (ALLOW / BLOCK / LOG / ALERT). Les règles sont évaluées par
priorité décroissante et la première qui matche gagne.

Inspiré du modèle pf (OpenBSD) et nftables — simple, expressif, rapide.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .engine import PacketEvent, Verdict


class Action(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    LOG = "log"
    ALERT = "alert"

    def to_verdict(self) -> Verdict:
        return Verdict[self.name]


@dataclass
class Rule:
    """
    Règle de filtrage déclarative.

    Champs None = wildcard (match tout).
    Champs avec valeur = doit correspondre.
    """
    name: str
    action: Action = Action.BLOCK
    priority: int = 100              # 0 = max priorité
    enabled: bool = True

    # Critères de matching
    src_cidr: Optional[str] = None
    dst_cidr: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    port_range: Optional[tuple[int, int]] = None
    protocol: Optional[str] = None   # TCP / UDP / ICMP
    direction: Optional[str] = None  # inbound / outbound
    process_re: Optional[str] = None # regex sur process_name

    # Métadonnées
    description: str = ""
    tags: list[str] = field(default_factory=list)
    hit_count: int = 0

    # Cache compilé
    _src_net: Optional[ipaddress._BaseNetwork] = field(default=None, init=False, repr=False)
    _dst_net: Optional[ipaddress._BaseNetwork] = field(default=None, init=False, repr=False)
    _proc_re: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.src_cidr:
            self._src_net = ipaddress.ip_network(self.src_cidr, strict=False)
        if self.dst_cidr:
            self._dst_net = ipaddress.ip_network(self.dst_cidr, strict=False)
        if self.process_re:
            self._proc_re = re.compile(self.process_re, re.IGNORECASE)

    def matches(self, evt: PacketEvent) -> bool:
        if not self.enabled:
            return False

        if self._src_net is not None:
            try:
                if ipaddress.ip_address(evt.src_addr) not in self._src_net:
                    return False
            except ValueError:
                return False
        if self._dst_net is not None:
            try:
                if ipaddress.ip_address(evt.dst_addr) not in self._dst_net:
                    return False
            except ValueError:
                return False
        if self.src_port is not None and evt.src_port != self.src_port:
            return False
        if self.dst_port is not None and evt.dst_port != self.dst_port:
            return False
        if self.port_range is not None:
            lo, hi = self.port_range
            if not (lo <= evt.dst_port <= hi):
                return False
        if self.protocol is not None and evt.protocol != self.protocol:
            return False
        if self.direction is not None and evt.direction != self.direction:
            return False
        if self._proc_re is not None:
            if not evt.process_name or not self._proc_re.search(evt.process_name):
                return False
        return True


class RuleEngine:
    """Évalue une liste ordonnée de règles."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._default = Action.ALLOW  # politique par défaut

    def set_default(self, action: Action) -> None:
        self._default = action

    def add(self, rule: Rule) -> None:
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)

    def remove(self, name: str) -> bool:
        for i, r in enumerate(self._rules):
            if r.name == name:
                del self._rules[i]
                return True
        return False

    def list(self) -> list[Rule]:
        return list(self._rules)

    def __call__(self, evt: PacketEvent) -> Optional[Verdict]:
        """Implémente le protocole FilterFn de l'Engine."""
        for r in self._rules:
            if r.matches(evt):
                r.hit_count += 1
                evt.matched_rule = r.name
                evt.tags.append(f"rule:{r.name}")
                return r.action.to_verdict()
        # Pas de match : on laisse les autres filtres décider
        return None


# Quelques règles utiles par défaut ----------------------------------------

def default_starter_rules() -> list[Rule]:
    """Ensemble de règles raisonnables pour débuter."""
    return [
        Rule(
            name="block-telnet",
            action=Action.BLOCK,
            priority=10,
            dst_port=23,
            protocol="TCP",
            description="Bloquer Telnet sortant — protocole non chiffré obsolète",
            tags=["security", "hardening"],
        ),
        Rule(
            name="block-smb-out",
            action=Action.BLOCK,
            priority=20,
            dst_port=445,
            protocol="TCP",
            direction="outbound",
            description="Bloquer SMB sortant vers Internet (prévention exfiltration)",
            tags=["security"],
        ),
        Rule(
            name="alert-rdp-in",
            action=Action.ALERT,
            priority=30,
            dst_port=3389,
            protocol="TCP",
            direction="inbound",
            description="Alerter sur toute tentative RDP entrante",
            tags=["security", "monitor"],
        ),
        Rule(
            name="block-bittorrent",
            action=Action.BLOCK,
            priority=50,
            port_range=(6881, 6889),
            protocol="TCP",
            description="Bloquer plage BitTorrent classique",
            tags=["p2p"],
        ),
    ]
