"""Vue des listes de blocage IP et DNS."""
from __future__ import annotations

import time

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QPushButton, QLineEdit, QInputDialog, QMessageBox, QSplitter, QTabWidget,
    QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView
)


COMMON_LISTS = [
    ("I-Blocklist Level1 (P2P monitors)", "https://list.iblocklist.com/?list=bt_level1&fileformat=p2p&archiveformat=zip", "p2p"),
    ("I-Blocklist Ads",                   "https://list.iblocklist.com/?list=bt_ads&fileformat=p2p&archiveformat=zip", "p2p"),
    ("I-Blocklist Spyware",               "https://list.iblocklist.com/?list=bt_spyware&fileformat=p2p&archiveformat=zip", "p2p"),
    ("FireHOL Level1",                    "https://iplists.firehol.org/files/firehol_level1.netset", "cidr"),
    ("Spamhaus DROP",                     "https://www.spamhaus.org/drop/drop.txt", "cidr"),
]


COMMON_DNS_LISTS = [
    ("StevenBlack Hosts (ads+malware)",   "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
    ("URLhaus",                            "https://urlhaus.abuse.ch/downloads/hostfile/"),
    ("OISD (small)",                       "https://small.oisd.nl/"),
]


class DownloadThread(QThread):
    finished_ok = pyqtSignal(str, int)
    failed = pyqtSignal(str, str)

    def __init__(self, fn, *args):
        super().__init__()
        self.fn = fn
        self.args = args

    def run(self):
        try:
            n = self.fn(*self.args)
            self.finished_ok.emit(self.args[0], n)
        except Exception as e:
            self.failed.emit(self.args[0], str(e))


class BlocklistView(QWidget):
    def __init__(self, orchestrator) -> None:
        super().__init__()
        self.orch = orchestrator

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)

        title = QLabel("Listes de blocage")
        title.setObjectName("Title")
        root.addWidget(title)

        tabs = QTabWidget()
        tabs.addTab(self._build_ip_tab(), "Listes IP")
        tabs.addTab(self._build_dns_tab(), "Listes DNS")
        tabs.addTab(self._build_ti_tab(), "Threat Intelligence")
        tabs.addTab(self._build_alerts_tab(), "Alertes")
        root.addWidget(tabs)

        self.alerts_timer = QTimer(self)
        self.alerts_timer.timeout.connect(self.refresh_alerts)
        self.alerts_timer.start(1500)

    # ---- Onglet IP ---------------------------------------------------

    def _build_ip_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        info = QLabel("Listes I-Blocklist (héritées de PeerBlock) + listes CIDR modernes.")
        info.setObjectName("Subtitle")
        lay.addWidget(info)

        actions = QHBoxLayout()
        add_url = QPushButton("Ajouter depuis URL...")
        add_url.clicked.connect(self.add_from_url)
        add_url.setObjectName("Primary")
        add_pre = QPushButton("Listes recommandées...")
        add_pre.clicked.connect(self.add_preset)
        remove = QPushButton("Supprimer")
        remove.setObjectName("Danger")
        remove.clicked.connect(self.remove_list)
        actions.addWidget(add_url)
        actions.addWidget(add_pre)
        actions.addWidget(remove)
        actions.addStretch()
        lay.addLayout(actions)

        self.ip_list = QListWidget()
        lay.addWidget(self.ip_list)

        self.refresh_ip()
        return w

    def refresh_ip(self) -> None:
        self.ip_list.clear()
        for bl in self.orch.blocklist.lists():
            it = QListWidgetItem(
                f"{bl.name}   ·   {bl.size:,} plages   ·   "
                f"{'activée' if bl.enabled else 'désactivée'}"
            )
            it.setData(Qt.ItemDataRole.UserRole, bl.name)
            self.ip_list.addItem(it)
        total = self.orch.blocklist.total_ranges()
        self.ip_list.addItem(f"────  Total fusionné : {total:,} plages indexées")

    def add_from_url(self) -> None:
        url, ok = QInputDialog.getText(self, "URL de la liste", "URL :")
        if not ok or not url.strip():
            return
        name, ok = QInputDialog.getText(self, "Nom", "Nom de la liste :")
        if not ok or not name.strip():
            return

        self._dl = DownloadThread(self.orch.blocklist.download_list, name, url, "auto")
        self._dl.finished_ok.connect(self._on_dl_done)
        self._dl.failed.connect(self._on_dl_failed)
        self._dl.start()
        QMessageBox.information(self, "Téléchargement", "Téléchargement en cours...")

    def add_preset(self) -> None:
        names = [n for n, _, _ in COMMON_LISTS]
        choice, ok = QInputDialog.getItem(self, "Listes recommandées",
                                           "Choisir :", names, 0, False)
        if not ok:
            return
        for n, url, fmt in COMMON_LISTS:
            if n == choice:
                self._dl = DownloadThread(self.orch.blocklist.download_list, n, url, fmt)
                self._dl.finished_ok.connect(self._on_dl_done)
                self._dl.failed.connect(self._on_dl_failed)
                self._dl.start()
                break

    def _on_dl_done(self, name: str, n: int) -> None:
        self.refresh_ip()
        QMessageBox.information(self, "OK", f"« {name} » importée — {n:,} plages.")

    def _on_dl_failed(self, name: str, err: str) -> None:
        QMessageBox.warning(self, "Erreur", f"Échec « {name} » :\n{err}")

    def remove_list(self) -> None:
        it = self.ip_list.currentItem()
        if not it:
            return
        name = it.data(Qt.ItemDataRole.UserRole)
        if not name:
            return
        self.orch.blocklist.remove_list(name)
        self.refresh_ip()

    # ---- Onglet DNS --------------------------------------------------

    def _build_dns_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        info = QLabel(f"Domaines bloqués : {self.orch.dns.total():,}")
        info.setObjectName("Subtitle")
        lay.addWidget(info)
        self.dns_info = info

        actions = QHBoxLayout()
        add_btn = QPushButton("Ajouter domaine...")
        add_btn.setObjectName("Primary")
        add_btn.clicked.connect(self.add_dns)
        import_btn = QPushButton("Importer liste hosts...")
        import_btn.clicked.connect(self.import_hosts)
        preset_btn = QPushButton("Listes recommandées...")
        preset_btn.clicked.connect(self.add_dns_preset)
        actions.addWidget(add_btn)
        actions.addWidget(import_btn)
        actions.addWidget(preset_btn)
        actions.addStretch()
        lay.addLayout(actions)

        self.dns_log = QTextEdit()
        self.dns_log.setReadOnly(True)
        self.dns_log.setPlainText(
            "Catégories disponibles :\n"
            "  - ads-tracking : publicités et trackers\n"
            "  - malware     : C2, distribution\n"
            "  - phishing    : sites frauduleux\n"
            "  - parental    : adultes / paris\n"
            "  - regex       : expressions régulières\n\n"
            "Les wildcards sont actifs : bloquer foo.com bloque *.foo.com.\n"
        )
        lay.addWidget(self.dns_log)
        return w

    def add_dns(self) -> None:
        d, ok = QInputDialog.getText(self, "Domaine", "Domaine à bloquer :")
        if ok and d.strip():
            self.orch.dns.add(d.strip(), category="user")
            self.dns_info.setText(f"Domaines bloqués : {self.orch.dns.total():,}")

    def import_hosts(self) -> None:
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(self, "Fichier hosts")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                n = self.orch.dns.load_hosts_file(f.read(), category="imported", source=path)
            QMessageBox.information(self, "OK", f"{n:,} domaines importés.")
            self.dns_info.setText(f"Domaines bloqués : {self.orch.dns.total():,}")
        except Exception as e:
            QMessageBox.warning(self, "Erreur", str(e))

    def add_dns_preset(self) -> None:
        names = [n for n, _ in COMMON_DNS_LISTS]
        choice, ok = QInputDialog.getItem(self, "Listes DNS recommandées",
                                           "Choisir :", names, 0, False)
        if not ok:
            return
        import urllib.request
        for n, url in COMMON_DNS_LISTS:
            if n == choice:
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "NextGenBlock/1.0"})
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        text = resp.read().decode("utf-8", errors="ignore")
                    nb = self.orch.dns.load_hosts_file(text, category="imported", source=url)
                    QMessageBox.information(self, "OK", f"{nb:,} domaines importés depuis {n}.")
                    self.dns_info.setText(f"Domaines bloqués : {self.orch.dns.total():,}")
                except Exception as e:
                    QMessageBox.warning(self, "Erreur", str(e))
                break

    # ---- Onglet Threat Intel -----------------------------------------

    def _build_ti_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        info = QLabel(f"IoCs en base : {self.orch.ti.total_iocs():,}")
        info.setObjectName("Subtitle")
        lay.addWidget(info)
        self.ti_info = info

        refresh_btn = QPushButton("Rafraîchir maintenant")
        refresh_btn.setObjectName("Primary")
        refresh_btn.clicked.connect(self.refresh_ti)
        lay.addWidget(refresh_btn)

        self.ti_list = QListWidget()
        lay.addWidget(self.ti_list)
        self.refresh_ti_list()
        return w

    def refresh_ti_list(self) -> None:
        self.ti_list.clear()
        for feed in self.orch.ti.list_feeds():
            status = "✓ activé" if feed.enabled else "○ désactivé"
            self.ti_list.addItem(
                f"{feed.name}  [{feed.category}]  conf={feed.confidence}  {status}"
            )

    def refresh_ti(self) -> None:
        self._ti_thread = DownloadThread(self._refresh_ti_worker, "Threat Intelligence")
        self._ti_thread.finished_ok.connect(self._on_ti_done)
        self._ti_thread.failed.connect(lambda n, e: QMessageBox.warning(self, "Erreur", e))
        self._ti_thread.start()
        QMessageBox.information(self, "TI", "Rafraîchissement en cours...")

    def _refresh_ti_worker(self, _name: str) -> int:
        self.orch.ti.refresh(force=True)
        return self.orch.ti.total_iocs()

    def _on_ti_done(self, _name, _n) -> None:
        self.ti_info.setText(f"IoCs en base : {self.orch.ti.total_iocs():,}")
        self.refresh_ti_list()

    # ---- Onglet Alertes ----------------------------------------------

    def _build_alerts_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        info = QLabel("Dernieres alertes IDS / IPS detectees en temps reel.")
        info.setObjectName("Subtitle")
        lay.addWidget(info)
        self.alerts_info = info

        actions = QHBoxLayout()
        refresh_btn = QPushButton("Actualiser")
        refresh_btn.setObjectName("Primary")
        refresh_btn.clicked.connect(self.refresh_alerts)
        actions.addWidget(refresh_btn)
        actions.addStretch()
        lay.addLayout(actions)

        self.alerts_table = QTableWidget(0, 6)
        self.alerts_table.setHorizontalHeaderLabels([
            "Heure", "Gravite", "Regle", "Source", "Cible", "Message"
        ])
        self.alerts_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        header = self.alerts_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        lay.addWidget(self.alerts_table)

        self.refresh_alerts()
        return w

    def refresh_alerts(self) -> None:
        if not hasattr(self, "alerts_table"):
            return

        alerts = list(self.orch.ids.alerts)
        alerts.reverse()
        self.alerts_info.setText(f"Dernieres alertes IDS / IPS : {len(alerts):,}")
        self.alerts_table.setRowCount(len(alerts))

        for row, alert in enumerate(alerts):
            values = [
                time.strftime("%H:%M:%S", time.localtime(alert.timestamp)),
                alert.severity,
                alert.rule,
                alert.src_ip,
                alert.dst_ip,
                alert.message,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if col in (1, 2):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.alerts_table.setItem(row, col, item)
