"""Thème sombre moderne pour Qt."""

DARK_QSS = """
* {
    font-family: "Segoe UI", "SF Pro Text", "Helvetica Neue", Arial;
    font-size: 10pt;
    color: #e8e8ea;
}

QMainWindow, QWidget {
    background-color: #14151a;
}

QFrame#Card {
    background-color: #1b1e26;
    border: 1px solid #2d3342;
    border-radius: 8px;
}

QFrame#Hero {
    background-color: #171b24;
    border: 1px solid #334155;
    border-radius: 8px;
}

QLabel#Title {
    font-size: 20pt;
    font-weight: 600;
    color: #ffffff;
}

QLabel#HeroTitle {
    font-size: 24pt;
    font-weight: 700;
    color: #ffffff;
    background: transparent;
}

QLabel#HeroLogo {
    background: transparent;
    padding-right: 6px;
}

QLabel#Subtitle {
    font-size: 10pt;
    color: #8a8c95;
}

QLabel#MetricValue {
    font-size: 25pt;
    font-weight: 700;
    color: #f8fafc;
}

QLabel#InfoValue {
    font-size: 12pt;
    font-weight: 600;
    color: #dbeafe;
}

QLabel#MetricLabel {
    font-size: 9pt;
    color: #8a8c95;
    text-transform: uppercase;
    letter-spacing: 1px;
}

QLabel#StatusOK {
    color: #86efac;
    background-color: rgba(34, 197, 94, 0.12);
    border: 1px solid rgba(34, 197, 94, 0.24);
    border-radius: 6px;
    padding: 5px 10px;
    font-weight: 600;
}
QLabel#StatusWarn {
    color: #fde68a;
    background-color: rgba(245, 158, 11, 0.12);
    border: 1px solid rgba(245, 158, 11, 0.25);
    border-radius: 6px;
    padding: 5px 10px;
    font-weight: 600;
}
QLabel#StatusError {
    color: #fecaca;
    background-color: rgba(239, 68, 68, 0.12);
    border: 1px solid rgba(239, 68, 68, 0.25);
    border-radius: 6px;
    padding: 5px 10px;
    font-weight: 600;
}

QPushButton {
    background-color: #2a2d39;
    color: #e8e8ea;
    border: 1px solid #353846;
    border-radius: 6px;
    padding: 7px 14px;
    font-weight: 500;
}
QPushButton:hover { background-color: #353846; }
QPushButton:pressed { background-color: #1f222b; }
QPushButton:disabled {
    color: #6b7280;
    background-color: #20232c;
    border-color: #2a2d39;
}
QPushButton#Primary {
    background-color: #2563eb;
    border-color: #2563eb;
}
QPushButton#Primary:hover { background-color: #3b82f6; }
QPushButton#Danger {
    background-color: #dc2626;
    border-color: #dc2626;
}
QPushButton#Danger:hover { background-color: #ef4444; }

QListWidget, QTableWidget, QTreeWidget, QTextEdit {
    background-color: #1b1e26;
    border: 1px solid #2d3342;
    border-radius: 6px;
    selection-background-color: #2563eb;
    alternate-background-color: #20232c;
}
QHeaderView::section {
    background-color: #202636;
    color: #b0b3bd;
    border: none;
    padding: 6px 8px;
    font-weight: 600;
}

QTabWidget::pane {
    border: none;
    background-color: #14151a;
}
QTabBar::tab {
    background-color: transparent;
    color: #8a8c95;
    padding: 10px 18px;
    border: none;
    font-weight: 500;
}
QTabBar::tab:selected {
    color: #ffffff;
    border-bottom: 2px solid #38bdf8;
}
QTabBar::tab:hover:!selected { color: #b0b3bd; }

QLineEdit, QComboBox, QSpinBox {
    background-color: #22242e;
    border: 1px solid #2a2d39;
    border-radius: 6px;
    padding: 6px 8px;
    color: #ffffff;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border-color: #38bdf8;
}
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #353846;
    border-radius: 3px;
    background: #22242e;
}
QCheckBox::indicator:checked {
    background: #2563eb;
    border-color: #2563eb;
}

QStatusBar {
    background: #121821;
    color: #8a8c95;
    border-top: 1px solid #263244;
}

QScrollBar:vertical {
    background: #14151a;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #2a2d39;
    border-radius: 5px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover { background: #353846; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""
