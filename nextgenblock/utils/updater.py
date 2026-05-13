"""Mise a jour non bloquante de l'application.

Le module reste volontairement conservateur : il ne fait quelque chose que si
le dossier courant est un depot Git et que git est disponible. Dans les autres
cas, il renvoie un statut lisible sans generer de trafic reseau inutile.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class UpdateResult:
    status: str
    message: str


class UpdateManager:
    def __init__(self, app_root: Path | None = None) -> None:
        self.app_root = app_root or Path(__file__).resolve().parents[2]

    def update(self) -> UpdateResult:
        if not (self.app_root / ".git").exists():
            return UpdateResult(
                "unavailable",
                "Aucune source de mise a jour Git n'est configuree.",
            )

        git = shutil.which("git")
        if not git:
            return UpdateResult(
                "unavailable",
                "Git n'est pas installe ou introuvable dans le PATH.",
            )

        try:
            proc = subprocess.run(
                [git, "pull", "--ff-only"],
                cwd=self.app_root,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except Exception as exc:
            return UpdateResult("error", f"Mise a jour impossible : {exc}")

        output = (proc.stdout or proc.stderr or "").strip()
        if proc.returncode != 0:
            return UpdateResult("error", output or "git pull a echoue.")
        if "Already up to date" in output or "Deja a jour" in output:
            return UpdateResult("current", "NextGenBlock est deja a jour.")
        return UpdateResult("updated", output or "NextGenBlock a ete mis a jour.")
