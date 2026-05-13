"""
NextGenBlock - Point d'entrée principal
Pare-feu nouvelle génération pour Windows.

Le mode par defaut est sans incidence reseau. Les droits administrateur ne
sont demandes que si la capture reelle WinDivert est activee dans la config :
    python run.py
"""
from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path


def is_admin() -> bool:
    """Vérifie si le processus a les privilèges administrateur Windows."""
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> None:
    """Tente de relancer le script en tant qu'administrateur."""
    if os.name != "nt":
        return
    params = " ".join(f'"{a}"' for a in sys.argv)
    exe = sys.executable
    pythonw = Path(exe).with_name("pythonw.exe")
    if pythonw.exists():
        exe = str(pythonw)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", exe, params, None, 1
    )


def main() -> int:
    if os.name != "nt":
        print("[!] NextGenBlock cible Windows uniquement.")
        print("    Sur un autre OS, l'application se lance en mode démo (capture simulée).")

    from nextgenblock.utils.config import Config
    cfg = Config.load()

    if os.name == "nt" and cfg.live_capture_enabled and not is_admin():
        print("[!] Privileges administrateur requis uniquement pour la capture reelle WinDivert.")
        print("    Relance en mode eleve...")
        relaunch_as_admin()
        return 0

    from nextgenblock.gui.main_window import launch_gui
    return launch_gui()


if __name__ == "__main__":
    sys.exit(main())
