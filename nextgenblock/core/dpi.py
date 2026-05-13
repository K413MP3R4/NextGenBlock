"""
Deep Packet Inspection (DPI).

Identifie le protocole applicatif réel d'un flux à partir de signatures sur
le payload, indépendamment du port. Similaire à nDPI / l7-filter.

Pour une démo réaliste sans dépendance externe, on implémente quelques
signatures clés. En production on brancherait nDPI ou Suricata.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .engine import PacketEvent, Verdict


@dataclass
class ProtocolSignature:
    name: str
    pattern: bytes | re.Pattern
    min_port: int = 0
    max_port: int = 65535
    category: str = "generic"   # web, p2p, voip, tunnel, malware...
    risk: int = 0                # 0-100


# Signatures L7 — détectent un protocole, port-agnostiques ----------------
SIGNATURES: list[ProtocolSignature] = [
    ProtocolSignature(
        name="HTTP",
        pattern=re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^\r\n]+ HTTP/1\."),
        category="web",
    ),
    ProtocolSignature(
        name="HTTP-Response",
        pattern=re.compile(rb"^HTTP/1\.[01] \d{3}"),
        category="web",
    ),
    ProtocolSignature(
        name="TLS-ClientHello",
        # 16 03 ?? ?? ?? 01 = TLS handshake + ClientHello
        pattern=re.compile(rb"^\x16\x03[\x00-\x04].{2}\x01", re.DOTALL),
        category="web",
    ),
    ProtocolSignature(
        name="SSH",
        pattern=re.compile(rb"^SSH-[12]\."),
        category="remote",
        risk=10,
    ),
    ProtocolSignature(
        name="BitTorrent-Handshake",
        pattern=re.compile(rb"^\x13BitTorrent protocol"),
        category="p2p",
        risk=40,
    ),
    ProtocolSignature(
        name="BitTorrent-DHT",
        pattern=re.compile(rb"^d1:ad2:id20:"),
        category="p2p",
        risk=40,
    ),
    ProtocolSignature(
        name="SMB",
        pattern=re.compile(rb"^\xfeSMB|^\xffSMB"),
        category="filesharing",
        risk=20,
    ),
    ProtocolSignature(
        name="Tor",
        # Reconnaissance partielle du handshake Tor
        pattern=re.compile(rb"^\x16\x03[\x00-\x03].{2}\x01.{2}\x03[\x00-\x03]", re.DOTALL),
        min_port=9001, max_port=9151,
        category="tunnel",
        risk=50,
    ),
    ProtocolSignature(
        name="DNS",
        pattern=re.compile(rb"^.{2}[\x00-\x01][\x00\x80-\x87].{6}", re.DOTALL),
        min_port=53, max_port=53,
        category="infra",
    ),
    ProtocolSignature(
        name="RDP",
        pattern=re.compile(rb"^\x03\x00..\x02\xf0"),
        category="remote",
        risk=30,
    ),
    ProtocolSignature(
        name="QUIC",
        # Premier byte avec long header flag bit
        pattern=re.compile(rb"^[\xc0-\xff].{4}\x00\x00\x00\x01", re.DOTALL),
        category="web",
    ),
    # Signatures malveillantes connues (démo)
    ProtocolSignature(
        name="MalwareC2-Generic",
        pattern=re.compile(rb"\x00\x00\x00\x6cBNDR|MZ\x90\x00\x03"),
        category="malware",
        risk=90,
    ),
]


class DPIEngine:
    """
    Inspecte le payload et identifie le protocole. Peut bloquer les
    catégories interdites.
    """

    def __init__(self) -> None:
        self.blocked_categories: set[str] = set()
        self.blocked_protocols: set[str] = set()
        self.stats: dict[str, int] = {}

    def block_category(self, cat: str) -> None:
        self.blocked_categories.add(cat)

    def unblock_category(self, cat: str) -> None:
        self.blocked_categories.discard(cat)

    def identify(self, payload: bytes, port: int = 0) -> Optional[ProtocolSignature]:
        if not payload:
            return None
        for sig in SIGNATURES:
            if port and not (sig.min_port <= port <= sig.max_port):
                continue
            if isinstance(sig.pattern, bytes):
                if payload.startswith(sig.pattern):
                    return sig
            else:
                if sig.pattern.search(payload[:256]):
                    return sig
        return None

    def __call__(self, evt: PacketEvent) -> Optional[Verdict]:
        sig = self.identify(evt.payload, port=evt.remote_port)
        if sig is None:
            return None

        self.stats[sig.name] = self.stats.get(sig.name, 0) + 1
        evt.tags.append(f"dpi:{sig.name}")
        evt.threat_score = max(evt.threat_score, sig.risk)

        if sig.category in self.blocked_categories or sig.name in self.blocked_protocols:
            return Verdict.BLOCK
        if sig.category == "malware":
            return Verdict.ALERT
        return None
