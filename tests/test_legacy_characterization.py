"""Jour 1 — filet de sécurité : ce que fait le script hérité AVANT refactoring.

Ces tests figent le comportement observable de legacy/log_watcher.py (sans SMTP ni fichier
incidents.db réel) pour vérifier ensuite que le nouveau domaine fait la même chose.
"""

import importlib
import sqlite3
from pathlib import Path
from types import ModuleType

import pytest

LINE = "Oct 14 09:00:00 host sshd[42]: Failed password for {user} from {ip}\n"


@pytest.fixture
def legacy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.chdir(tmp_path)  # le module ouvre incidents.db à l'import : le garder hors du dépôt
    module = importlib.import_module("legacy.log_watcher")
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE incidents (ip TEXT, user TEXT)")
    monkeypatch.setattr(module, "DB", db)
    return module


def _run(legacy: ModuleType, tmp_path: Path, lines: list[str]) -> tuple[list[str], list[tuple]]:
    log = tmp_path / "auth.log"
    log.write_text("".join(lines))
    alerts: list[str] = []
    watcher = legacy.LogWatcher(str(log))
    watcher.alert = alerts.append  # pas de vrai SMTP
    watcher.run()
    return alerts, legacy.DB.execute("SELECT ip, user FROM incidents").fetchall()


def test_five_failures_same_ip_trigger_one_alert(legacy: ModuleType, tmp_path: Path) -> None:
    alerts, rows = _run(legacy, tmp_path, [LINE.format(user="root", ip="10.0.0.66")] * 7)
    assert alerts == ["10.0.0.66"]  # une seule alerte, au 5e échec, pas au 6e ni au 7e
    assert rows == [("10.0.0.66", "root")]


def test_failures_spread_over_ips_trigger_nothing(legacy: ModuleType, tmp_path: Path) -> None:
    lines = [LINE.format(user="root", ip=f"10.0.0.{i}") for i in range(4) for _ in range(4)]
    alerts, rows = _run(legacy, tmp_path, lines)
    assert alerts == []
    assert rows == []
