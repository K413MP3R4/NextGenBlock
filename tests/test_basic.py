"""
Tests basiques de NextGenBlock — vérifient que les modules s'importent
et que la logique de filtrage est correcte sans nécessiter WinDivert.

Lancement :
    cd D:\\Claude Code\\NextGenBlock
    python -m pytest tests/  (si pytest installé)
    ou :
    python tests/test_basic.py
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_packet_event():
    from nextgenblock.core.engine import PacketEvent
    evt = PacketEvent(src_addr="1.1.1.1", dst_addr="2.2.2.2",
                      src_port=12345, dst_port=443, protocol="TCP",
                      direction="outbound")
    assert evt.remote_addr == "2.2.2.2"
    assert evt.remote_port == 443
    print("[OK] PacketEvent")


def test_rules():
    from nextgenblock.core.engine import PacketEvent, Verdict
    from nextgenblock.core.rules import RuleEngine, Rule, Action

    eng = RuleEngine()
    eng.add(Rule(name="block-port-23", action=Action.BLOCK, dst_port=23))
    eng.add(Rule(name="allow-https", action=Action.ALLOW, dst_port=443, priority=5))

    e1 = PacketEvent("1.1.1.1", "2.2.2.2", dst_port=23, protocol="TCP")
    e2 = PacketEvent("1.1.1.1", "2.2.2.2", dst_port=443, protocol="TCP")
    e3 = PacketEvent("1.1.1.1", "2.2.2.2", dst_port=80, protocol="TCP")

    assert eng(e1) == Verdict.BLOCK
    assert e1.matched_rule == "block-port-23"
    assert eng(e2) == Verdict.ALLOW
    assert eng(e3) is None
    print("[OK] RuleEngine")


def test_logger_persists_events():
    import gc
    import tempfile
    from nextgenblock.core.engine import PacketEvent, Verdict
    from nextgenblock.utils.logger import EventLogger

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        db = os.path.join(td, "logs.db")
        logger = EventLogger(db_path=db)
        evt = PacketEvent("1.1.1.1", "2.2.2.2", dst_port=443)
        evt.matched_rule = "unit-test-rule"
        evt.src_company = "Cloudflare"
        evt.src_country = "US"
        logger.log(evt, Verdict.BLOCK)
        logger.flush()
        rows = logger.recent(limit=5)
        assert len(rows) == 1
        assert rows[0]["verdict"] == "block"
        assert rows[0]["rule"] == "unit-test-rule"
        assert rows[0]["src_company"] == "Cloudflare"
        assert rows[0]["src_country"] == "US"
        del rows
        del logger
        gc.collect()
    print("[OK] EventLogger persistence")


def test_ip_company_lookup():
    from nextgenblock.core.ip_info import company_for_ip

    assert company_for_ip("8.8.8.8") == "Google"
    assert company_for_ip("1.1.1.1") == "Cloudflare"
    assert company_for_ip("192.168.1.1") == "Reseau prive"
    assert company_for_ip("not-an-ip") is None
    print("[OK] IP company lookup")


def test_flag_country_label():
    from nextgenblock.gui.logs_view import _flag_for_country

    assert _flag_for_country("US")
    assert _flag_for_country("FR")
    assert _flag_for_country("EU")
    assert _flag_for_country("bad") == ""
    print("[OK] Country flag labels")


def test_updater_without_git_is_safe():
    import tempfile
    from pathlib import Path
    from nextgenblock.utils.updater import UpdateManager

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        result = UpdateManager(Path(td)).update()
    assert result.status == "unavailable"
    print("[OK] Updater safe without git source")


def test_blocklist():
    from nextgenblock.core.engine import PacketEvent
    from nextgenblock.core.blocklist import BlocklistManager, Blocklist, IPRange
    import ipaddress

    mgr = BlocklistManager()
    mgr.add_list(Blocklist(name="t", ranges=[
        IPRange(int(ipaddress.ip_address("10.0.0.0")),
                int(ipaddress.ip_address("10.0.0.255")), "demo")
    ]))
    assert mgr.is_blocked("10.0.0.5") is not None
    assert mgr.is_blocked("11.0.0.5") is None
    print("[OK] BlocklistManager")


def test_blocklist_p2p_parser():
    from nextgenblock.core.blocklist import BlocklistManager
    sample = """
# commentaire
Bad ISP:1.2.3.4-1.2.3.255
Worse ISP:10.0.0.0-10.0.0.10
"""
    ranges = BlocklistManager.parse_p2p_format(sample)
    assert len(ranges) == 2
    print("[OK] parse_p2p_format")


def test_dpi():
    from nextgenblock.core.engine import PacketEvent
    from nextgenblock.core.dpi import DPIEngine

    dpi = DPIEngine()
    e = PacketEvent("1.1.1.1", "2.2.2.2", dst_port=443,
                    payload=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    dpi(e)
    assert any(t.startswith("dpi:HTTP") for t in e.tags)
    print("[OK] DPI signatures")


def test_dns_parse():
    from nextgenblock.core.dns_filter import _parse_dns_qname
    # Requête DNS pour example.com
    pkt = bytes([
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, ord('e'), ord('x'), ord('a'), ord('m'), ord('p'), ord('l'), ord('e'),
        0x03, ord('c'), ord('o'), ord('m'),
        0x00, 0x00, 0x01, 0x00, 0x01
    ])
    assert _parse_dns_qname(pkt) == "example.com"
    print("[OK] DNS parser")


def test_dns_filter():
    from nextgenblock.core.dns_filter import DnsFilter
    f = DnsFilter()
    f.add("evil.com")
    assert f.is_blocked("evil.com") is not None
    assert f.is_blocked("sub.evil.com") is not None  # wildcard
    assert f.is_blocked("good.com") is None
    print("[OK] DnsFilter wildcards")


def test_ids_portscan():
    from nextgenblock.core.engine import PacketEvent
    from nextgenblock.core.ids import PortScanDetector

    det = PortScanDetector(window=10, vertical_threshold=5)
    alert = None
    for p in range(20, 30):
        e = PacketEvent("attacker.com", "victim.com", dst_port=p, protocol="TCP")
        a = det.observe(e)
        if a:
            alert = a
            break
    assert alert is not None
    assert "vertical" in alert.rule
    print("[OK] IDS port-scan detection")


def test_geoip():
    from nextgenblock.core.engine import PacketEvent
    from nextgenblock.core.geoip import GeoIPFilter

    geo = GeoIPFilter()
    assert geo.country_of("8.8.8.8") == "US"
    geo.block("US")
    e = PacketEvent("1.1.1.1", "8.8.8.8", direction="outbound", dst_port=53)
    from nextgenblock.core.engine import Verdict
    assert geo(e) == Verdict.BLOCK
    print("[OK] GeoIP")


def test_threat_intel_cidr_lookup():
    from nextgenblock.core.engine import PacketEvent, Verdict
    from nextgenblock.core.threat_intel import ThreatIntel, IoCEntry

    ti = ThreatIntel()
    ti.add_ioc(IoCEntry("203.0.113.0/24", "test-net", 90, "unit"))
    assert ti.lookup("203.0.113.42") is not None
    assert ti.lookup("203.0.114.42") is None
    evt = PacketEvent("192.168.1.2", "203.0.113.42", direction="outbound")
    assert ti(evt) == Verdict.BLOCK
    print("[OK] ThreatIntel CIDR lookup")


def test_orchestrator_applies_config():
    import tempfile
    from nextgenblock.orchestrator import Orchestrator
    from nextgenblock.utils.config import Config

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        cfg = Config(
            enable_dns_filter=False,
            enable_dpi=False,
            enable_threat_intel=False,
            ids_ban_duration=123,
            ids_brute_threshold=3,
            ids_scan_threshold=4,
            ti_min_confidence=88,
            log_db_path=os.path.join(td, "logs.db"),
        )
        orch = Orchestrator(config=cfg, simulate=True)
        filter_names = [name for name, _ in orch.engine._filters]
        assert "dns" not in filter_names
        assert "dpi" not in filter_names
        assert "threat-intel" not in filter_names
        assert orch.ids._ban_ttl == 123
        assert orch.ids.brute.threshold == 3
        assert orch.ids.scan.vt == 4
        assert orch.ti.min_confidence == 88
    print("[OK] Orchestrator config applied")


def test_orchestrator_defaults_to_no_impact_mode():
    import tempfile
    from nextgenblock.orchestrator import Orchestrator
    from nextgenblock.utils.config import Config

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        cfg = Config(log_db_path=os.path.join(td, "logs.db"))
        orch = Orchestrator(config=cfg)
        assert orch.simulate is True
        assert orch.engine.simulate is True
        assert orch.engine.passive is True
    print("[OK] Orchestrator default no-impact mode")


def test_live_capture_requires_explicit_config():
    import tempfile
    from nextgenblock.orchestrator import Orchestrator
    from nextgenblock.utils.config import Config

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        cfg = Config(
            simulate_mode=False,
            live_capture_enabled=True,
            passive_capture_mode=True,
            log_db_path=os.path.join(td, "logs.db"),
        )
        orch = Orchestrator(config=cfg)
        assert orch.simulate is False
        assert orch.engine.passive is True
    print("[OK] Live capture explicit and passive")


def test_orchestrator_simulation():
    import tempfile
    from nextgenblock.orchestrator import Orchestrator
    from nextgenblock.utils.config import Config
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        cfg = Config(log_db_path=os.path.join(td, "logs.db"), enable_threat_intel=False)
        orch = Orchestrator(config=cfg, simulate=True)
        orch.start()
        time.sleep(1.5)
        summary = orch.get_summary()
        orch.stop()
    assert summary["engine"]["total"] > 0
    print(f"[OK] Orchestrator simulation: {summary['engine']['total']} paquets traités")


if __name__ == "__main__":
    print("=" * 60)
    print(" NextGenBlock - Tests basiques")
    print("=" * 60)
    test_packet_event()
    test_rules()
    test_logger_persists_events()
    test_ip_company_lookup()
    test_flag_country_label()
    test_updater_without_git_is_safe()
    test_blocklist()
    test_blocklist_p2p_parser()
    test_dpi()
    test_dns_parse()
    test_dns_filter()
    test_ids_portscan()
    test_geoip()
    test_threat_intel_cidr_lookup()
    test_orchestrator_applies_config()
    test_orchestrator_defaults_to_no_impact_mode()
    test_live_capture_requires_explicit_config()
    test_orchestrator_simulation()
    print("=" * 60)
    print(" Tous les tests passent ")
    print("=" * 60)
