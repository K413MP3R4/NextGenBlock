"""Vue des règles utilisateur."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QPushButton, QDialog, QFormLayout, QLineEdit,
    QComboBox, QSpinBox, QDialogButtonBox, QMessageBox
)

from ..core.rules import Rule, Action


class RuleDialog(QDialog):
    def __init__(self, parent=None, rule: Rule | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Règle" if rule else "Nouvelle règle")
        self.setMinimumWidth(420)

        layout = QFormLayout(self)
        self.name = QLineEdit(rule.name if rule else "")
        self.action = QComboBox()
        self.action.addItems([a.value for a in Action])
        if rule:
            self.action.setCurrentText(rule.action.value)
        self.priority = QSpinBox()
        self.priority.setRange(0, 1000)
        self.priority.setValue(rule.priority if rule else 100)
        self.dst_cidr = QLineEdit(rule.dst_cidr if rule and rule.dst_cidr else "")
        self.dst_cidr.setPlaceholderText("ex: 192.168.0.0/16 ou 1.2.3.4")
        self.dst_port = QSpinBox()
        self.dst_port.setRange(0, 65535)
        self.dst_port.setValue(rule.dst_port if rule and rule.dst_port else 0)
        self.protocol = QComboBox()
        self.protocol.addItems(["", "TCP", "UDP", "ICMP"])
        if rule and rule.protocol:
            self.protocol.setCurrentText(rule.protocol)
        self.direction = QComboBox()
        self.direction.addItems(["", "inbound", "outbound"])
        if rule and rule.direction:
            self.direction.setCurrentText(rule.direction)
        self.process_re = QLineEdit(rule.process_re if rule and rule.process_re else "")
        self.process_re.setPlaceholderText("regex sur nom d'exécutable")
        self.description = QLineEdit(rule.description if rule else "")

        layout.addRow("Nom :", self.name)
        layout.addRow("Action :", self.action)
        layout.addRow("Priorité (0=max) :", self.priority)
        layout.addRow("CIDR destination :", self.dst_cidr)
        layout.addRow("Port destination (0=tous) :", self.dst_port)
        layout.addRow("Protocole :", self.protocol)
        layout.addRow("Direction :", self.direction)
        layout.addRow("Application (regex) :", self.process_re)
        layout.addRow("Description :", self.description)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def to_rule(self) -> Rule:
        return Rule(
            name=self.name.text().strip() or "rule",
            action=Action(self.action.currentText()),
            priority=self.priority.value(),
            dst_cidr=self.dst_cidr.text().strip() or None,
            dst_port=self.dst_port.value() or None,
            protocol=self.protocol.currentText() or None,
            direction=self.direction.currentText() or None,
            process_re=self.process_re.text().strip() or None,
            description=self.description.text().strip(),
        )


class RulesView(QWidget):
    def __init__(self, orchestrator) -> None:
        super().__init__()
        self.orch = orchestrator

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        header = QHBoxLayout()
        title = QLabel("Règles de filtrage")
        title.setObjectName("Title")
        header.addWidget(title)
        header.addStretch()
        add_btn = QPushButton("+ Nouvelle règle")
        add_btn.setObjectName("Primary")
        add_btn.clicked.connect(self.add_rule)
        del_btn = QPushButton("Supprimer")
        del_btn.setObjectName("Danger")
        del_btn.clicked.connect(self.del_rule)
        header.addWidget(add_btn)
        header.addWidget(del_btn)
        root.addLayout(header)

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(
            ["Nom", "Action", "Prio", "Dest CIDR", "Port", "Proto", "Hits", "Description"]
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        root.addWidget(self.table)

        self.refresh()

    def refresh(self) -> None:
        rules = self.orch.rules.list()
        self.table.setRowCount(len(rules))
        for i, r in enumerate(rules):
            self.table.setItem(i, 0, QTableWidgetItem(r.name))
            self.table.setItem(i, 1, QTableWidgetItem(r.action.value.upper()))
            self.table.setItem(i, 2, QTableWidgetItem(str(r.priority)))
            self.table.setItem(i, 3, QTableWidgetItem(r.dst_cidr or "-"))
            self.table.setItem(i, 4, QTableWidgetItem(str(r.dst_port or "-")))
            self.table.setItem(i, 5, QTableWidgetItem(r.protocol or "-"))
            self.table.setItem(i, 6, QTableWidgetItem(str(r.hit_count)))
            self.table.setItem(i, 7, QTableWidgetItem(r.description))
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setStretchLastSection(True)

    def add_rule(self) -> None:
        dlg = RuleDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.orch.rules.add(dlg.to_rule())
            self.refresh()

    def del_rule(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        name = self.table.item(row, 0).text()
        if QMessageBox.question(self, "Confirmer", f"Supprimer la règle « {name} » ?") \
                == QMessageBox.StandardButton.Yes:
            self.orch.rules.remove(name)
            self.refresh()
