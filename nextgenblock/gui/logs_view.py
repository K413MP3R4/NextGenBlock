"""Vue Logs — affichage des évènements récents."""
from __future__ import annotations

import time

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QPushButton, QComboBox, QLineEdit, QHeaderView
)


VERDICT_COLORS = {
    "block": "#f87171",
    "alert": "#fb923c",
    "log":   "#fbbf24",
    "allow": "#4ade80",
}


class LogsView(QWidget):
    def __init__(self, orchestrator) -> None:
        super().__init__()
        self.orch = orchestrator

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        # En-tête
        header = QHBoxLayout()
        title = QLabel("Journal des évènements")
        title.setObjectName("Title")
        header.addWidget(title)
        header.addStretch()

        self.filter_verdict = QComboBox()
        self.filter_verdict.addItems(["Tous", "block", "allow", "alert", "log"])
        self.filter_verdict.currentTextChanged.connect(self.refresh)
        header.addWidget(QLabel("Verdict :"))
        header.addWidget(self.filter_verdict)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Filtrer (IP, port, app, tag)...")
        self.search.textChanged.connect(self.refresh)
        self.search.setMinimumWidth(220)
        header.addWidget(self.search)

        refresh_btn = QPushButton("Actualiser")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)

        root.addLayout(header)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(10)
        self.table.setHorizontalHeaderLabels(
            ["Heure", "Verdict", "Dir.", "Proto", "Source", "Destination", "Compagnie", "Pays", "Application", "Tags / Règle"]
        )
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        root.addWidget(self.table)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(2000)

    def refresh(self) -> None:
        v = self.filter_verdict.currentText()
        verdict = None if v == "Tous" else v
        try:
            rows = self.orch.logger.recent(limit=300, verdict=verdict)
        except Exception:
            rows = []

        text = self.search.text().lower().strip()
        if text:
            rows = [
                r for r in rows
                if text in (r.get("src_addr") or "").lower()
                or text in (r.get("dst_addr") or "").lower()
                or text in (r.get("src_company") or "").lower()
                or text in (r.get("dst_company") or "").lower()
                or text in (r.get("src_country") or "").lower()
                or text in (r.get("dst_country") or "").lower()
                or text in str(r.get("dst_port") or "")
                or text in (r.get("process_name") or "").lower()
                or text in (r.get("tags") or "").lower()
                or text in (r.get("rule") or "").lower()
            ]

        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            ts = time.strftime("%H:%M:%S", time.localtime(r.get("ts", 0)))
            self._set(i, 0, ts)
            verdict_item = QTableWidgetItem(r.get("verdict", "").upper())
            color = VERDICT_COLORS.get(r.get("verdict", ""), "#e8e8ea")
            verdict_item.setForeground(QColor(color))
            self.table.setItem(i, 1, verdict_item)
            self._set(i, 2, r.get("direction", ""))
            self._set(i, 3, r.get("protocol", ""))
            self._set(i, 4, f"{r.get('src_addr','')}:{r.get('src_port','')}")
            self._set(i, 5, f"{r.get('dst_addr','')}:{r.get('dst_port','')}")
            self._set(i, 6, self._company_text(r))
            self._set(i, 7, self._country_text(r))
            self._set(i, 8, r.get("process_name") or "")
            tags = r.get("tags") or ""
            rule = r.get("rule") or ""
            extra = f"{rule}  ·  {tags}" if rule else tags
            self._set(i, 9, extra)

        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setStretchLastSection(True)

    def _set(self, row: int, col: int, text: str) -> None:
        self.table.setItem(row, col, QTableWidgetItem(str(text)))

    def _company_text(self, row: dict) -> str:
        if row.get("direction") == "outbound":
            return row.get("dst_company") or "Inconnu"
        if row.get("direction") == "inbound":
            return row.get("src_company") or "Inconnu"
        return row.get("dst_company") or row.get("src_company") or "Inconnu"

    def _country_text(self, row: dict) -> str:
        if row.get("direction") == "outbound":
            code = row.get("dst_country")
        elif row.get("direction") == "inbound":
            code = row.get("src_country")
        else:
            code = row.get("dst_country") or row.get("src_country")
        if not code:
            return "Inconnu"
        label = f"{_flag_for_country(code)} {code}"
        blocked = {c.upper() for c in self.orch.config.blocked_countries}
        if code.upper() in blocked or row.get("verdict") in ("block", "alert"):
            return f"{label} bloque"
        return label


def _flag_for_country(code: str) -> str:
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in code)
