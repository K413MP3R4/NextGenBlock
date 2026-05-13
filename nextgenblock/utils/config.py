"""Configuration utilisateur persistante (YAML)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

try:
    import yaml
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False
    import json


CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".nextgenblock")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.yaml" if _HAVE_YAML else "config.json")


@dataclass
class Config:
    # Comportement général
    simulate_mode: bool = True
    auto_start_engine: bool = True
    auto_hide_after_start_seconds: int = 5
    minimize_to_tray: bool = True
    start_with_windows: bool = False
    auto_update_on_start: bool = True
    live_capture_enabled: bool = False
    passive_capture_mode: bool = True
    default_policy: str = "allow"        # allow / block

    # Modules activés
    enable_blocklist: bool = True
    enable_dpi: bool = True
    enable_app_filter: bool = False
    enable_ids: bool = True
    enable_dns_filter: bool = True
    enable_geoip: bool = False
    enable_threat_intel: bool = True

    # IDS
    ids_ban_duration: int = 600
    ids_brute_threshold: int = 10
    ids_scan_threshold: int = 15

    # GeoIP
    blocked_countries: list[str] = field(default_factory=list)
    allowed_countries: list[str] = field(default_factory=list)

    # Threat Intel
    ti_min_confidence: int = 70
    ti_auto_refresh: bool = True

    # GUI
    theme: str = "dark"                  # dark / light
    show_notifications: bool = True

    # Persistance
    log_db_path: Optional[str] = None

    def save(self) -> None:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        data = asdict(self)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            if _HAVE_YAML:
                yaml.safe_dump(data, f, sort_keys=False)
            else:
                json.dump(data, f, indent=2)

    @classmethod
    def load(cls) -> "Config":
        if not os.path.exists(CONFIG_FILE):
            return cls()
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                if _HAVE_YAML:
                    data = yaml.safe_load(f) or {}
                else:
                    data = json.load(f)
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        except Exception as e:
            print(f"[config] erreur chargement: {e}")
            return cls()
