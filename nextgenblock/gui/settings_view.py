"""Vue Paramètres."""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QFormLayout, QCheckBox, QSpinBox,
    QLineEdit, QPushButton, QLabel, QFrame, QHBoxLayout, QComboBox,
    QMessageBox
)

from ..utils.config import Config
from ..utils.windows_startup import is_start_with_windows_enabled, set_start_with_windows


def _section(title: str) -> tuple[QFrame, QFormLayout]:
    f = QFrame()
    f.setObjectName("Card")
    v = QVBoxLayout(f)
    v.setContentsMargins(20, 16, 20, 16)
    lbl = QLabel(title)
    lbl.setObjectName("MetricLabel")
    v.addWidget(lbl)
    form = QFormLayout()
    v.addLayout(form)
    return f, form


class SettingsView(QWidget):
    def __init__(self, orchestrator) -> None:
        super().__init__()
        self.orch = orchestrator
        self.cfg: Config = orchestrator.config

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        title = QLabel("Paramètres")
        title.setObjectName("Title")
        root.addWidget(title)

        # ---- Experience Windows ----
        app_frame, f = _section("EXPERIENCE WINDOWS")
        self.cb_auto_start = QCheckBox("Activer automatiquement la protection au lancement")
        self.cb_auto_start.setChecked(self.cfg.auto_start_engine)
        self.cb_tray = QCheckBox("Reduire dans la zone de notification")
        self.cb_tray.setChecked(self.cfg.minimize_to_tray)
        self.cb_windows_start = QCheckBox("Demarrer NextGenBlock avec Windows")
        self.cb_windows_start.setChecked(self.cfg.start_with_windows or is_start_with_windows_enabled())
        self.sp_auto_hide = QSpinBox(); self.sp_auto_hide.setRange(0, 60)
        self.sp_auto_hide.setValue(self.cfg.auto_hide_after_start_seconds)
        self.cb_auto_update = QCheckBox("Verifier les mises a jour au lancement")
        self.cb_auto_update.setChecked(self.cfg.auto_update_on_start)
        f.addRow(self.cb_auto_start)
        f.addRow(self.cb_tray)
        f.addRow(self.cb_windows_start)
        f.addRow("Cacher la fenetre apres lancement (s) :", self.sp_auto_hide)
        f.addRow(self.cb_auto_update)
        root.addWidget(app_frame)

        # ---- Securite reseau ----
        network_frame, f = _section("SECURITE RESEAU")
        self.cb_live = QCheckBox("Activer la capture reseau reelle avec WinDivert")
        self.cb_live.setChecked(self.cfg.live_capture_enabled)
        self.cb_passive = QCheckBox("Mode passif sans blocage de connexion")
        self.cb_passive.setChecked(self.cfg.passive_capture_mode)
        f.addRow(self.cb_live)
        f.addRow(self.cb_passive)
        root.addWidget(network_frame)

        # ---- Modules ----
        modules_frame, f = _section("MODULES DE FILTRAGE")
        self.cb_blocklist = QCheckBox("Listes de blocage IP (héritage PeerBlock)")
        self.cb_blocklist.setChecked(self.cfg.enable_blocklist)
        self.cb_dpi = QCheckBox("Deep Packet Inspection (DPI)")
        self.cb_dpi.setChecked(self.cfg.enable_dpi)
        self.cb_app = QCheckBox("Filtrage par application (résolution PID)")
        self.cb_app.setChecked(self.cfg.enable_app_filter)
        self.cb_ids = QCheckBox("IDS/IPS (port-scan, brute-force, flood)")
        self.cb_ids.setChecked(self.cfg.enable_ids)
        self.cb_dns = QCheckBox("Filtrage DNS (sinkhole)")
        self.cb_dns.setChecked(self.cfg.enable_dns_filter)
        self.cb_geo = QCheckBox("GeoIP (blocage par pays)")
        self.cb_geo.setChecked(self.cfg.enable_geoip)
        self.cb_ti = QCheckBox("Threat Intelligence (flux IoC)")
        self.cb_ti.setChecked(self.cfg.enable_threat_intel)
        for cb in [self.cb_blocklist, self.cb_dpi, self.cb_app, self.cb_ids,
                   self.cb_dns, self.cb_geo, self.cb_ti]:
            f.addRow(cb)
        root.addWidget(modules_frame)

        # ---- IDS ----
        ids_frame, f = _section("IDS / IPS")
        self.sp_ban = QSpinBox(); self.sp_ban.setRange(60, 86400)
        self.sp_ban.setValue(self.cfg.ids_ban_duration)
        self.sp_brute = QSpinBox(); self.sp_brute.setRange(2, 100)
        self.sp_brute.setValue(self.cfg.ids_brute_threshold)
        self.sp_scan = QSpinBox(); self.sp_scan.setRange(5, 200)
        self.sp_scan.setValue(self.cfg.ids_scan_threshold)
        f.addRow("Durée du bannissement auto (s) :", self.sp_ban)
        f.addRow("Seuil brute-force (tentatives/min) :", self.sp_brute)
        f.addRow("Seuil port-scan (ports/10s) :", self.sp_scan)
        root.addWidget(ids_frame)

        # ---- GeoIP ----
        geo_frame, f = _section("GEOIP")
        self.le_blocked = QLineEdit(",".join(self.cfg.blocked_countries))
        self.le_blocked.setPlaceholderText("Codes ISO séparés par virgule : CN,RU,KP")
        self.le_allowed = QLineEdit(",".join(self.cfg.allowed_countries))
        self.le_allowed.setPlaceholderText("Whitelist stricte (si non vide)")
        f.addRow("Pays bloqués :", self.le_blocked)
        f.addRow("Pays autorisés (whitelist) :", self.le_allowed)
        root.addWidget(geo_frame)

        # ---- Threat Intel ----
        ti_frame, f = _section("THREAT INTELLIGENCE")
        self.sp_conf = QSpinBox(); self.sp_conf.setRange(0, 100)
        self.sp_conf.setValue(self.cfg.ti_min_confidence)
        self.cb_ti_refresh = QCheckBox("Rafraîchir automatiquement (toutes les 24h)")
        self.cb_ti_refresh.setChecked(self.cfg.ti_auto_refresh)
        f.addRow("Confiance min. pour bloquer :", self.sp_conf)
        f.addRow(self.cb_ti_refresh)
        root.addWidget(ti_frame)

        # ---- Boutons ----
        actions = QHBoxLayout()
        save_btn = QPushButton("Enregistrer")
        save_btn.setObjectName("Primary")
        save_btn.clicked.connect(self.save)
        actions.addStretch()
        actions.addWidget(save_btn)
        root.addLayout(actions)
        root.addStretch()

    def save(self) -> None:
        if self.cb_live.isChecked() and not self.cb_passive.isChecked():
            choice = QMessageBox.warning(
                self,
                "Mode blocage actif",
                "Le mode blocage actif peut interrompre ou ralentir la connexion Internet. "
                "Pour garantir aucune incidence, gardez le mode passif active.",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Ok,
                QMessageBox.StandardButton.Cancel,
            )
            if choice != QMessageBox.StandardButton.Ok:
                return

        c = self.cfg
        c.enable_blocklist = self.cb_blocklist.isChecked()
        c.enable_dpi = self.cb_dpi.isChecked()
        c.enable_app_filter = self.cb_app.isChecked()
        c.enable_ids = self.cb_ids.isChecked()
        c.enable_dns_filter = self.cb_dns.isChecked()
        c.enable_geoip = self.cb_geo.isChecked()
        c.enable_threat_intel = self.cb_ti.isChecked()
        c.live_capture_enabled = self.cb_live.isChecked()
        c.simulate_mode = not c.live_capture_enabled
        c.passive_capture_mode = self.cb_passive.isChecked()
        c.auto_start_engine = self.cb_auto_start.isChecked()
        c.minimize_to_tray = self.cb_tray.isChecked()
        c.start_with_windows = self.cb_windows_start.isChecked()
        c.auto_hide_after_start_seconds = self.sp_auto_hide.value()
        c.auto_update_on_start = self.cb_auto_update.isChecked()
        c.ids_ban_duration = self.sp_ban.value()
        c.ids_brute_threshold = self.sp_brute.value()
        c.ids_scan_threshold = self.sp_scan.value()
        c.blocked_countries = [x.strip().upper() for x in self.le_blocked.text().split(",") if x.strip()]
        c.allowed_countries = [x.strip().upper() for x in self.le_allowed.text().split(",") if x.strip()]
        c.ti_min_confidence = self.sp_conf.value()
        c.ti_auto_refresh = self.cb_ti_refresh.isChecked()
        c.save()
        try:
            set_start_with_windows(c.start_with_windows)
        except Exception as e:
            QMessageBox.warning(
                self,
                "Demarrage Windows",
                f"Impossible de mettre a jour le demarrage Windows :\n{e}",
            )

        # Application immédiate
        self.orch.apply_config(rebuild_filters=True)
        win = self.window()
        if hasattr(win, "mode_label") and hasattr(win, "_mode_text"):
            win.mode_label.setText(win._mode_text())
        QMessageBox.information(self, "Parametres", "Configuration appliquee.")
