"""
Orchestrateur — instancie et câble tous les modules.

Permet de démarrer un pare-feu opérationnel en quelques lignes :

    orch = Orchestrator(simulate=True)
    orch.start()
    ...
    orch.stop()
"""
from __future__ import annotations

from typing import Callable, Optional

from .core.engine import FirewallEngine, PacketEvent, Verdict
from .core.rules import RuleEngine, Action, default_starter_rules
from .core.blocklist import BlocklistManager, builtin_demo_list
from .core.dpi import DPIEngine
from .core.app_filter import AppFilter
from .core.ids import IDSEngine
from .core.dns_filter import DnsFilter
from .core.geoip import GeoIPFilter
from .core.ip_info import company_for_ip
from .core.threat_intel import ThreatIntel
from .utils.config import Config
from .utils.logger import EventLogger


class Orchestrator:
    def __init__(self, config: Optional[Config] = None,
                 simulate: bool = False) -> None:
        self.config = config or Config.load()
        self.simulate = simulate or self.config.simulate_mode or not self.config.live_capture_enabled

        self.engine = FirewallEngine(
            simulate=self.simulate,
            passive=self.config.passive_capture_mode,
        )
        self.rules = RuleEngine()
        self.blocklist = BlocklistManager()
        self.dpi = DPIEngine()
        self.app_filter = AppFilter()
        self.ids = IDSEngine(
            ban_ttl=self.config.ids_ban_duration,
            brute_threshold=self.config.ids_brute_threshold,
            scan_threshold=self.config.ids_scan_threshold,
        )
        self.dns = DnsFilter()
        self.geo = GeoIPFilter()
        self.ti = ThreatIntel()

        self.logger = EventLogger(db_path=self.config.log_db_path)
        self.engine.on_packet = self._on_packet
        self.on_alert: Optional[Callable] = None
        self.ids.on_alert = self._on_ids_alert

        self._wire_defaults()
        self.apply_config(rebuild_filters=False)
        self._wire_filters()

    # ---- Setup -------------------------------------------------------

    def _wire_defaults(self) -> None:
        # Règles par défaut
        for r in default_starter_rules():
            self.rules.add(r)

        # Liste de démo
        self.blocklist.add_list(builtin_demo_list())

        # Quelques entrées DNS classiques (démo)
        for d in [
            "doubleclick.net", "googleadservices.com", "googlesyndication.com",
            "scorecardresearch.com", "googletagmanager.com",
            "malware-traffic-analysis.net",
        ]:
            self.dns.add(d, category="ads-tracking", source="builtin")
        for d in ["evil-c2.example", "phishing-site.example"]:
            self.dns.add(d, category="malware", source="builtin")

        # Pays bloqués depuis config
        for c in self.config.blocked_countries:
            self.geo.block(c)
        for c in self.config.allowed_countries:
            self.geo.allow_only(c)

    def _wire_filters(self) -> None:
        """Ordre d'évaluation = ordre d'enregistrement."""
        cfg = self.config

        # 1. IDS/IPS en premier (auto-ban prioritaire)
        if cfg.enable_ids:
            self.engine.add_filter("ids", self.ids)

        # 2. Règles utilisateur explicites (priorité haute)
        self.engine.add_filter("rules", self.rules)

        # 3. Threat Intel (réputation)
        if cfg.enable_threat_intel:
            self.engine.add_filter("threat-intel", self.ti)

        # 4. Blocklists statiques
        if cfg.enable_blocklist:
            self.engine.add_filter("blocklist", self.blocklist)

        # 5. GeoIP
        if cfg.enable_geoip:
            self.engine.add_filter("geoip", self.geo)

        # 6. DNS
        if cfg.enable_dns_filter:
            self.engine.add_filter("dns", self.dns)

        # 7. App filter
        if cfg.enable_app_filter:
            self.engine.add_filter("app", self.app_filter)

        # 8. DPI (le plus coûteux, en dernier)
        if cfg.enable_dpi:
            self.engine.add_filter("dpi", self.dpi)

    def apply_config(self, rebuild_filters: bool = True) -> None:
        """Applique les reglages runtime aux modules."""
        cfg = self.config
        self.simulate = cfg.simulate_mode or not cfg.live_capture_enabled
        self.engine.simulate = self.simulate
        self.engine.passive = cfg.passive_capture_mode
        self.ids.configure(
            ban_ttl=cfg.ids_ban_duration,
            brute_threshold=cfg.ids_brute_threshold,
            scan_threshold=cfg.ids_scan_threshold,
        )
        self.ids.on_alert = self._on_ids_alert
        self.ti.min_confidence = cfg.ti_min_confidence
        try:
            self.rules.set_default(Action(cfg.default_policy))
        except ValueError:
            self.rules.set_default(Action.ALLOW)
        self.geo.blocked_countries = {c.upper() for c in cfg.blocked_countries}
        self.geo.allowed_countries = {c.upper() for c in cfg.allowed_countries}
        if rebuild_filters:
            self.engine.clear_filters()
            self._wire_filters()

    # ---- Callbacks ---------------------------------------------------

    def _on_packet(self, evt: PacketEvent, verdict: Verdict) -> None:
        evt.src_company = company_for_ip(evt.src_addr)
        evt.dst_company = company_for_ip(evt.dst_addr)
        evt.src_country = self.geo.country_of(evt.src_addr)
        evt.dst_country = self.geo.country_of(evt.dst_addr)
        self.logger.log(evt, verdict)

    def _on_ids_alert(self, alert) -> None:
        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception:
                pass

    # ---- Cycle de vie ------------------------------------------------

    def start(self) -> None:
        # Rafraîchir TI en arrière-plan si activé
        if self.config.ti_auto_refresh and self.config.enable_threat_intel:
            import threading
            threading.Thread(target=self.ti.refresh, daemon=True).start()
        self.engine.start()

    def stop(self) -> None:
        self.engine.stop()
        self.logger.flush()

    def get_summary(self) -> dict:
        return {
            "engine": self.engine.get_stats(),
            "rules": len(self.rules.list()),
            "blocklist_ranges": self.blocklist.total_ranges(),
            "dns_blocked": self.dns.total(),
            "ti_iocs": self.ti.total_iocs(),
            "ids_alerts": len(self.ids.alerts),
            "ids_bans": len(self.ids.list_banned()),
        }
