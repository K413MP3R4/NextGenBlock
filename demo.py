"""
Demo NextGenBlock — lance le moteur en mode SIMULATION sans GUI ni admin.

Affiche en console le verdict appliqué à chaque paquet synthétique généré.
Idéal pour comprendre la chaîne de filtres sans installation lourde.

    python demo.py
"""
from __future__ import annotations

import time

from nextgenblock.orchestrator import Orchestrator
from nextgenblock.core.engine import Verdict


def main() -> None:
    print("=" * 70)
    print(" NextGenBlock — Démo en mode SIMULATION")
    print(" (aucun paquet réel n'est intercepté — trafic synthétique uniquement)")
    print("=" * 70)

    orch = Orchestrator(simulate=True)

    def on_packet(evt, verdict: Verdict) -> None:
        marker = {
            Verdict.ALLOW: ".",
            Verdict.BLOCK: "X",
            Verdict.ALERT: "!",
            Verdict.LOG:   "L",
        }[verdict]
        rule = evt.matched_rule or "-"
        tags = ",".join(evt.tags[:3])
        print(f" [{marker}] {evt.direction:8s} {evt.src_addr:>15}:{evt.src_port:<5} "
              f"-> {evt.dst_addr:>15}:{evt.dst_port:<5} {evt.protocol:4s} "
              f"verdict={verdict.value:6s} rule={rule:20s} tags=[{tags}]")

    orch.engine.on_packet = on_packet

    def on_alert(alert) -> None:
        print(f"\n  *** ALERTE [{alert.severity.upper()}/{alert.rule}] : {alert.message}\n")

    orch.on_alert = on_alert

    orch.start()
    try:
        print("\nTrafic synthétique pendant 8 secondes...\n")
        time.sleep(8)
    finally:
        orch.stop()

    print("\n" + "=" * 70)
    summary = orch.get_summary()
    print(" Résumé :")
    print(f"   Paquets analysés : {summary['engine']['total']}")
    print(f"   Autorisés        : {summary['engine']['allowed']}")
    print(f"   Bloqués          : {summary['engine']['blocked']}")
    print(f"   Loggés           : {summary['engine']['logged']}")
    print(f"   Alertés          : {summary['engine']['alerted']}")
    print(f"   Erreurs          : {summary['engine']['errors']}")
    print(f"   Règles actives   : {summary['rules']}")
    print(f"   Plages IP        : {summary['blocklist_ranges']}")
    print(f"   Domaines DNS     : {summary['dns_blocked']}")
    print("=" * 70)


if __name__ == "__main__":
    main()
