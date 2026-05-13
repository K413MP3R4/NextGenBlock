"""
Filtrage par application.

Mappe un paquet (5-tuple) au processus Windows qui l'a généré, via psutil.
Permet de bloquer "tout sauf navigateur" ou "seul torrent.exe", à la manière
de Little Snitch / GlassWire / Windows Firewall Control.

Cache LRU pour ne pas frapper psutil à chaque paquet.
"""
from __future__ import annotations

import re
import threading
import time
from collections import OrderedDict
from typing import Optional

from .engine import PacketEvent, Verdict


class _LRU:
    def __init__(self, maxsize: int = 4096) -> None:
        self._d: OrderedDict = OrderedDict()
        self.maxsize = maxsize
        self._lock = threading.Lock()

    def get(self, k):
        with self._lock:
            if k in self._d:
                self._d.move_to_end(k)
                return self._d[k]
        return None

    def put(self, k, v) -> None:
        with self._lock:
            self._d[k] = v
            self._d.move_to_end(k)
            if len(self._d) > self.maxsize:
                self._d.popitem(last=False)


class AppFilter:
    """
    Filtre par exécutable. Politique :
      * default_allow=True  => liste noire (blocklist d'apps)
      * default_allow=False => liste blanche (whitelist stricte)
    """

    def __init__(self, default_allow: bool = True, ttl: float = 5.0) -> None:
        self.default_allow = default_allow
        self.blocked: set[re.Pattern] = set()
        self.allowed: set[re.Pattern] = set()
        self._cache = _LRU()
        self._ttl = ttl

    def block_app(self, name_re: str) -> None:
        self.blocked.add(re.compile(name_re, re.IGNORECASE))

    def allow_app(self, name_re: str) -> None:
        self.allowed.add(re.compile(name_re, re.IGNORECASE))

    # ---- Résolution PID/processus ------------------------------------

    def _resolve_process(self, evt: PacketEvent) -> Optional[str]:
        try:
            import psutil
        except ImportError:
            return None

        key = (evt.src_addr, evt.src_port, evt.dst_addr, evt.dst_port, evt.protocol)
        cached = self._cache.get(key)
        if cached and (time.time() - cached[1]) < self._ttl:
            return cached[0]

        proto_kind = "tcp" if evt.protocol == "TCP" else "udp" if evt.protocol == "UDP" else None
        if proto_kind is None:
            return None

        try:
            conns = psutil.net_connections(kind=proto_kind)
        except (psutil.AccessDenied, psutil.Error):
            return None

        local = (evt.src_addr, evt.src_port) if evt.direction == "outbound" \
                else (evt.dst_addr, evt.dst_port)
        for c in conns:
            if c.laddr and c.laddr.port == local[1] and (c.laddr.ip == local[0] or c.laddr.ip in ("0.0.0.0", "::")):
                if c.pid:
                    try:
                        name = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        name = None
                    self._cache.put(key, (name, time.time()))
                    return name
        return None

    def __call__(self, evt: PacketEvent) -> Optional[Verdict]:
        name = evt.process_name or self._resolve_process(evt)
        evt.process_name = name
        if not name:
            return None

        for pat in self.blocked:
            if pat.search(name):
                evt.tags.append(f"app-block:{name}")
                return Verdict.BLOCK

        if not self.default_allow:
            # Mode whitelist : refuser si pas autorisé
            for pat in self.allowed:
                if pat.search(name):
                    return None
            evt.tags.append(f"app-deny:{name}")
            return Verdict.BLOCK
        return None
