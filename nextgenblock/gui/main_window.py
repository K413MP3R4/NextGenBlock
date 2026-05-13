"""Fenêtre principale PyQt6."""
from __future__ import annotations

import sys
import threading
from pathlib import Path

from PyQt6.QtCore import QEvent, Qt, QTimer
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QToolBar, QStatusBar,
    QLabel, QPushButton, QWidget, QHBoxLayout, QMessageBox, QMenu,
    QScrollArea, QSystemTrayIcon, QStyle
)

from ..orchestrator import Orchestrator
from ..utils.config import Config
from ..utils.updater import UpdateManager
from .theme import DARK_QSS
from .dashboard import Dashboard
from .logs_view import LogsView
from .rules_view import RulesView
from .blocklist_view import BlocklistView
from .settings_view import SettingsView


APP_ROOT = Path(__file__).resolve().parents[2]
APP_ICON = APP_ROOT / "assets" / "nextgenblock.ico"


class MainWindow(QMainWindow):
    def __init__(self, simulate: bool = False) -> None:
        super().__init__()
        import os
        self.config = Config.load()
        if os.environ.get("NGB_AUTO_START", "").lower() in ("1", "true", "yes"):
            self.config.auto_start_engine = True
        if os.environ.get("NGB_AUTO_HIDE_SECONDS", "").isdigit():
            self.config.auto_hide_after_start_seconds = int(os.environ["NGB_AUTO_HIDE_SECONDS"])
        self.orch = Orchestrator(config=self.config, simulate=simulate)

        self.setWindowTitle("NextGenBlock — Pare-feu nouvelle génération")
        self.resize(1280, 800)

        self._build_toolbar()
        self._build_tabs()
        self._build_statusbar()
        self._engine_running = False
        self._really_quit = False
        self._tray_notice_shown = False
        self._auto_hide_remaining = 0
        self._auto_hide_timer = QTimer(self)
        self._auto_hide_timer.timeout.connect(self._update_auto_hide_countdown)
        self._update_manager = UpdateManager()
        self._build_tray()

        # Hook alertes IDS -> notifications
        self.orch.on_alert = self._on_alert
        self._alert_timer = QTimer(self)
        self._alert_timer.timeout.connect(self._update_status)
        self._alert_timer.start(1000)

        if self.config.auto_start_engine:
            QTimer.singleShot(250, self.toggle_engine)
            if self.config.auto_hide_after_start_seconds > 0:
                QTimer.singleShot(500, self.start_auto_hide_countdown)
        if self.config.auto_update_on_start:
            QTimer.singleShot(1000, self.update_in_background)
        QTimer.singleShot(0, self.snap_to_left)

    # ---- Construction de l'UI ----------------------------------------

    def _build_toolbar(self) -> None:
        tb = QToolBar()
        tb.setMovable(False)
        self.addToolBar(tb)

        self.start_btn = QPushButton("Demarrer")
        self.start_btn.setObjectName("Primary")
        self.start_btn.clicked.connect(self.toggle_engine)
        tb.addWidget(self.start_btn)

        tb.addSeparator()
        spacer = QWidget()
        spacer.setSizePolicy(spacer.sizePolicy().horizontalPolicy().Expanding,
                             spacer.sizePolicy().verticalPolicy().Preferred)
        tb.addWidget(spacer)

        self.mode_label = QLabel(self._mode_text())
        self.mode_label.setObjectName("Subtitle")
        tb.addWidget(self.mode_label)

    def _mode_text(self) -> str:
        if self.orch.simulate:
            return " Mode : SANS INCIDENCE "
        if self.config.passive_capture_mode:
            return " Mode : PASSIF "
        return " Mode : BLOCAGE ACTIF "

    def _build_tabs(self) -> None:
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.dashboard = Dashboard(self.orch)
        self.logs_view = LogsView(self.orch)
        self.rules_view = RulesView(self.orch)
        self.blocklist_view = BlocklistView(self.orch)
        self.settings_view = SettingsView(self.orch)

        self.tabs.addTab(self._scrollable(self.dashboard), "Tableau de bord")
        self.tabs.addTab(self.logs_view,       "Journal")
        self.tabs.addTab(self.rules_view,      "Règles")
        self.tabs.addTab(self._scrollable(self.blocklist_view), "Listes")
        self.tabs.addTab(self._scrollable(self.settings_view), "Paramètres")
        self.setCentralWidget(self.tabs)

    def _scrollable(self, widget: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidget(widget)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        return scroll

    def _build_statusbar(self) -> None:
        bar = QStatusBar()
        self.setStatusBar(bar)
        self.status_msg = QLabel("Prêt")
        bar.addWidget(self.status_msg)
        self.status_stats = QLabel("")
        bar.addPermanentWidget(self.status_stats)

    def _build_tray(self) -> None:
        self.tray = None
        self.tray_toggle_action = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        icon = QIcon(str(APP_ICON)) if APP_ICON.exists() else self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        self.setWindowIcon(icon)
        self.tray = QSystemTrayIcon(icon, self)
        self.tray.setToolTip("NextGenBlock")

        menu = QMenu(self)
        open_action = QAction("Ouvrir NextGenBlock", self)
        open_action.triggered.connect(self.show_from_tray)
        menu.addAction(open_action)

        self.tray_toggle_action = QAction("Suspendre", self)
        self.tray_toggle_action.triggered.connect(self.toggle_engine)
        menu.addAction(self.tray_toggle_action)

        update_action = QAction("Mettre a jour", self)
        update_action.triggered.connect(self.update_in_background)
        menu.addAction(update_action)

        menu.addSeparator()
        quit_action = QAction("Quitter", self)
        quit_action.triggered.connect(self.quit_from_tray)
        menu.addAction(quit_action)

        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._on_tray_activated)
        self.tray.show()
        self._update_tray_actions()

    # ---- Actions ----------------------------------------------------

    def toggle_engine(self) -> None:
        if not self._engine_running:
            try:
                self.orch.start()
                self._engine_running = True
                self.start_btn.setText("Arreter")
                self.start_btn.setObjectName("Danger")
                self.start_btn.style().unpolish(self.start_btn)
                self.start_btn.style().polish(self.start_btn)
                self.dashboard.set_running(True)
                if self.orch.simulate or self.config.passive_capture_mode:
                    self.status_msg.setText("Moteur actif - aucun blocage de la connexion")
                else:
                    self.status_msg.setText("Moteur actif - blocage reseau en cours")
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Impossible de démarrer :\n{e}")
        else:
            self.orch.stop()
            self._engine_running = False
            self.start_btn.setText("Demarrer")
            self.start_btn.setObjectName("Primary")
            self.start_btn.style().unpolish(self.start_btn)
            self.start_btn.style().polish(self.start_btn)
            self.dashboard.set_running(False)
            self.status_msg.setText("Moteur arrêté")

        self._update_tray_actions()

    def show_from_tray(self) -> None:
        self._auto_hide_timer.stop()
        self._auto_hide_remaining = 0
        self.showNormal()
        self.snap_to_left()
        self.raise_()
        self.activateWindow()

    def snap_to_left(self) -> None:
        screen = self.screen() or QApplication.primaryScreen()
        if not screen:
            return
        available = screen.availableGeometry()
        target_outer_width = max(520, available.width() // 2)
        target_outer_height = available.height()

        # QMainWindow.setGeometry() positions the client area, while the native
        # title bar lives in the surrounding frame. Account for that frame so
        # minimize/maximize/close remain visible after snapping to the screen.
        frame = self.frameGeometry()
        client = self.geometry()
        left_frame = client.left() - frame.left()
        top_frame = client.top() - frame.top()
        right_frame = frame.right() - client.right()
        bottom_frame = frame.bottom() - client.bottom()

        target_client_width = max(520, target_outer_width - left_frame - right_frame)
        target_client_height = max(400, target_outer_height - top_frame - bottom_frame)
        self.resize(target_client_width, target_client_height)
        self.move(available.left() + left_frame, available.top() + top_frame)
        self._correct_snap_to_available_area()
        QTimer.singleShot(50, self._correct_snap_to_available_area)

    def _correct_snap_to_available_area(self) -> None:
        screen = self.screen() or QApplication.primaryScreen()
        if not screen:
            return
        available = screen.availableGeometry()
        frame = self.frameGeometry()

        height_delta = available.height() - frame.height()
        if height_delta:
            self.resize(self.width(), max(400, self.height() + height_delta))
            frame = self.frameGeometry()

        self.move(
            self.x() + available.left() - frame.left(),
            self.y() + available.top() - frame.top(),
        )

    def start_auto_hide_countdown(self) -> None:
        if not self.config.minimize_to_tray or not self.tray or self._really_quit:
            return
        self._auto_hide_remaining = self.config.auto_hide_after_start_seconds
        if self._auto_hide_remaining <= 0:
            return
        self._update_auto_hide_countdown()
        self._auto_hide_timer.start(1000)

    def _update_auto_hide_countdown(self) -> None:
        if self._auto_hide_remaining <= 0:
            self._auto_hide_timer.stop()
            self.hide_to_tray()
            return

        suffix = "s" if self._auto_hide_remaining > 1 else ""
        self.status_msg.setText(
            f"Reduction dans la zone de notification dans {self._auto_hide_remaining} seconde{suffix}"
        )
        self._auto_hide_remaining -= 1

    def hide_to_tray(self) -> None:
        if self.config.minimize_to_tray and self.tray and not self._really_quit:
            self._auto_hide_timer.stop()
            self._auto_hide_remaining = 0
            self.hide()

    def quit_from_tray(self) -> None:
        self._really_quit = True
        if self._engine_running:
            self.orch.stop()
            self._engine_running = False
        if self.tray:
            self.tray.hide()
        QApplication.quit()

    def _on_tray_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self.show_from_tray()

    def _update_tray_actions(self) -> None:
        if self.tray_toggle_action:
            self.tray_toggle_action.setText("Suspendre" if self._engine_running else "Reprendre")
        if self.tray:
            state = "actif" if self._engine_running else "suspendu"
            self.tray.setToolTip(f"NextGenBlock - {state}")

    def update_in_background(self) -> None:
        def worker() -> None:
            result = self._update_manager.update()
            QTimer.singleShot(0, lambda: self._on_update_finished(result))

        threading.Thread(target=worker, daemon=True).start()

    def _on_update_finished(self, result) -> None:
        self.status_msg.setText(result.message)
        if self.tray and result.status in ("updated", "error"):
            self.tray.showMessage(
                "NextGenBlock",
                result.message,
                QSystemTrayIcon.MessageIcon.Information,
                3000,
            )

    def _on_alert(self, alert) -> None:
        # Affichage statusbar (non-bloquant)
        self.status_msg.setText(f"⚠ ALERTE [{alert.rule}] {alert.message}")

    def _update_status(self) -> None:
        s = self.orch.get_summary()
        e = s["engine"]
        self.status_stats.setText(
            f"Total: {e.get('total',0):,}  ·  "
            f"Bloqués: {e.get('blocked',0):,}  ·  "
            f"Alertes: {s['ids_alerts']:,}  ·  "
            f"IoCs: {s['ti_iocs']:,}"
        )

    def closeEvent(self, event) -> None:
        if self._really_quit or not self.tray or not self.config.minimize_to_tray:
            if self._engine_running:
                self.orch.stop()
            event.accept()
            return

        event.ignore()
        self.hide_to_tray()
        if not self._tray_notice_shown:
            self.tray.showMessage(
                "NextGenBlock",
                "L'application reste active dans la zone de notification.",
                QSystemTrayIcon.MessageIcon.Information,
                2500,
            )
            self._tray_notice_shown = True

    def changeEvent(self, event) -> None:
        if (
            event.type() == QEvent.Type.WindowStateChange
            and self.isMinimized()
            and self.tray
        ):
            QTimer.singleShot(0, self.hide)
        super().changeEvent(event)


def launch_gui() -> int:
    import os
    simulate = os.environ.get("NGB_SIMULATE", "").lower() in ("1", "true", "yes")
    # Sous non-Windows ou sans pydivert : forcer la simulation
    if os.name != "nt":
        simulate = True

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    if APP_ICON.exists():
        app.setWindowIcon(QIcon(str(APP_ICON)))
    app.setStyleSheet(DARK_QSS)
    app.setApplicationName("NextGenBlock")

    win = MainWindow(simulate=simulate)
    win.show()
    return app.exec()
