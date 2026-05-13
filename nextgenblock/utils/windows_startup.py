"""Gestion du demarrage automatique Windows."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path


SHORTCUT_NAME = "NextGenBlock.lnk"


def app_root() -> Path:
    return Path(__file__).resolve().parents[2]


def startup_shortcut_path() -> Path:
    startup = Path(os.environ.get("APPDATA", "")) / (
        "Microsoft/Windows/Start Menu/Programs/Startup"
    )
    return startup / SHORTCUT_NAME


def set_start_with_windows(enabled: bool) -> None:
    """Cree ou supprime le raccourci de demarrage de l'utilisateur courant."""
    path = startup_shortcut_path()
    if not enabled:
        if path.exists():
            path.unlink()
        return

    root = app_root()
    launcher = root / "Lancer_NextGenBlock.cmd"
    icon = root / "assets" / "nextgenblock.ico"
    path.parent.mkdir(parents=True, exist_ok=True)

    script = (
        "$shell=New-Object -ComObject WScript.Shell;"
        f"$lnk=$shell.CreateShortcut('{_ps(path)}');"
        f"$lnk.TargetPath='{_ps(launcher)}';"
        f"$lnk.WorkingDirectory='{_ps(root)}';"
        f"$lnk.IconLocation='{_ps(icon)}';"
        "$lnk.Description='NextGenBlock - demarrage automatique';"
        "$lnk.Save();"
    )
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        check=True,
        capture_output=True,
        text=True,
    )


def is_start_with_windows_enabled() -> bool:
    return startup_shortcut_path().exists()


def _ps(path: Path) -> str:
    return str(path).replace("'", "''")
