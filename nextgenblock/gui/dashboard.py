"""Vue Dashboard — métriques + graphes temps réel."""
from __future__ import annotations

import collections
import time
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QFrame
)


APP_ROOT = Path(__file__).resolve().parents[2]
APP_LOGO = APP_ROOT / "assets" / "nextgenblock.png"


def _card(title: str, value_widget: QLabel) -> QFrame:
    card = QFrame()
    card.setObjectName("Card")
    lay = QVBoxLayout(card)
    lay.setContentsMargins(20, 16, 20, 16)
    t = QLabel(title)
    t.setObjectName("MetricLabel")
    lay.addWidget(t)
    lay.addWidget(value_widget)
    return card


class Dashboard(QWidget):
    def __init__(self, orchestrator) -> None:
        super().__init__()
        self.orch = orchestrator

        self._chart_history: collections.deque = collections.deque(maxlen=60)
        self._last_total = 0

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # ---- Titre ----
        hero = QFrame()
        hero.setObjectName("Hero")
        header = QHBoxLayout(hero)
        header.setContentsMargins(20, 16, 20, 16)
        if APP_LOGO.exists():
            logo = QLabel()
            pixmap = QPixmap(str(APP_LOGO)).scaled(
                36, 36,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            logo.setPixmap(pixmap)
            logo.setFixedSize(38, 38)
            logo.setObjectName("HeroLogo")
            logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
            header.addWidget(logo)
        title = QLabel("NextGenBlock")
        title.setObjectName("HeroTitle")
        header.addWidget(title)
        header.addStretch()
        self.mode_label = QLabel("Connexion preservee")
        self.mode_label.setObjectName("StatusOK")
        header.addWidget(self.mode_label)
        self.status_label = QLabel("Inactif")
        self.status_label.setObjectName("StatusWarn")
        header.addWidget(self.status_label)
        root.addWidget(hero)

        status_grid = QGridLayout()
        status_grid.setSpacing(12)
        self.lbl_mode = QLabel("Sans incidence"); self.lbl_mode.setObjectName("InfoValue")
        self.lbl_tray = QLabel("Zone de notification active"); self.lbl_tray.setObjectName("InfoValue")
        self.lbl_policy = QLabel("Politique: autoriser"); self.lbl_policy.setObjectName("InfoValue")
        status_grid.addWidget(_card("Mode reseau", self.lbl_mode), 0, 0)
        status_grid.addWidget(_card("Fenetre", self.lbl_tray), 0, 1)
        status_grid.addWidget(_card("Regle par defaut", self.lbl_policy), 0, 2)
        root.addLayout(status_grid)

        # ---- Grille de métriques ----
        grid = QGridLayout()
        grid.setSpacing(12)

        self.lbl_total = QLabel("0");      self.lbl_total.setObjectName("MetricValue")
        self.lbl_blocked = QLabel("0");    self.lbl_blocked.setObjectName("MetricValue")
        self.lbl_allowed = QLabel("0");    self.lbl_allowed.setObjectName("MetricValue")
        self.lbl_alerts = QLabel("0");     self.lbl_alerts.setObjectName("MetricValue")
        self.lbl_pps = QLabel("0");        self.lbl_pps.setObjectName("MetricValue")
        self.lbl_iocs = QLabel("0");       self.lbl_iocs.setObjectName("MetricValue")
        self.lbl_dns = QLabel("0");        self.lbl_dns.setObjectName("MetricValue")
        self.lbl_bans = QLabel("0");       self.lbl_bans.setObjectName("MetricValue")

        grid.addWidget(_card("Paquets analysés", self.lbl_total),    0, 0)
        grid.addWidget(_card("Paquets bloqués",  self.lbl_blocked),  0, 1)
        grid.addWidget(_card("Paquets autorisés",self.lbl_allowed),  0, 2)
        grid.addWidget(_card("Alertes IDS",      self.lbl_alerts),   0, 3)
        grid.addWidget(_card("Paquets/sec",      self.lbl_pps),      1, 0)
        grid.addWidget(_card("IoCs en base",     self.lbl_iocs),     1, 1)
        grid.addWidget(_card("Domaines DNS",     self.lbl_dns),      1, 2)
        grid.addWidget(_card("IPs bannies (IPS)",self.lbl_bans),     1, 3)
        root.addLayout(grid)

        # ---- Graphe ----
        try:
            import pyqtgraph as pg
            self._pg = pg
            chart_frame = QFrame()
            chart_frame.setObjectName("Card")
            cl = QVBoxLayout(chart_frame)
            cl.setContentsMargins(16, 12, 16, 16)
            ct = QLabel("Trafic en temps réel (paquets/sec)")
            ct.setObjectName("MetricLabel")
            cl.addWidget(ct)
            self.plot = pg.PlotWidget(background="#1c1e26")
            self.plot.showGrid(x=False, y=True, alpha=0.2)
            self.plot.setLabel("left", "pkt/s", color="#8a8c95")
            self.curve_total = self.plot.plot(pen=pg.mkPen("#6366f1", width=2))
            self.curve_block = self.plot.plot(pen=pg.mkPen("#f87171", width=2))
            cl.addWidget(self.plot)
            root.addWidget(chart_frame, stretch=1)
        except ImportError:
            self._pg = None
            placeholder = QLabel("(Installer pyqtgraph pour voir les graphes temps réel)")
            placeholder.setObjectName("Subtitle")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            root.addWidget(placeholder, stretch=1)

        # Timer de rafraîchissement
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)

    def set_running(self, running: bool) -> None:
        if running:
            self.status_label.setText("Actif")
            self.status_label.setObjectName("StatusOK")
        else:
            self.status_label.setText("Inactif")
            self.status_label.setObjectName("StatusWarn")
        # Forcer le réapplication du style
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def refresh(self) -> None:
        s = self.orch.get_summary()
        eng = s["engine"]
        total = eng.get("total", 0)
        blocked = eng.get("blocked", 0)

        self.lbl_total.setText(f"{total:,}")
        self.lbl_blocked.setText(f"{blocked:,}")
        self.lbl_allowed.setText(f"{eng.get('allowed', 0):,}")
        self.lbl_alerts.setText(f"{s['ids_alerts']:,}")
        self.lbl_iocs.setText(f"{s['ti_iocs']:,}")
        self.lbl_dns.setText(f"{s['dns_blocked']:,}")
        self.lbl_bans.setText(f"{s['ids_bans']:,}")
        if self.orch.simulate:
            self.lbl_mode.setText("Sans incidence")
            self.mode_label.setText("Connexion preservee")
            self.mode_label.setObjectName("StatusOK")
        elif self.orch.config.passive_capture_mode:
            self.lbl_mode.setText("Observation passive")
            self.mode_label.setText("Mode passif")
            self.mode_label.setObjectName("StatusOK")
        else:
            self.lbl_mode.setText("Blocage actif")
            self.mode_label.setText("Filtrage actif")
            self.mode_label.setObjectName("StatusWarn")
        self.mode_label.style().unpolish(self.mode_label)
        self.mode_label.style().polish(self.mode_label)
        self.lbl_tray.setText(
            "Zone de notification active" if self.orch.config.minimize_to_tray else "Fermeture classique"
        )
        self.lbl_policy.setText(f"Politique: {self.orch.config.default_policy}")

        # Calcul pps
        delta = total - self._last_total
        self._last_total = total
        self.lbl_pps.setText(f"{delta}")

        # Mise à jour du graphe
        self._chart_history.append((delta, blocked))
        if self._pg is not None:
            ys_total = [h[0] for h in self._chart_history]
            block_deltas = [0] + [
                self._chart_history[i][1] - self._chart_history[i-1][1]
                for i in range(1, len(self._chart_history))
            ]
            xs = list(range(len(ys_total)))
            self.curve_total.setData(xs, ys_total)
            self.curve_block.setData(xs, block_deltas)
