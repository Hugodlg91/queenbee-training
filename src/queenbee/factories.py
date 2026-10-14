"""Fabrique abstraite : chaque fabrique livre une famille cohérente de composants."""

from __future__ import annotations

import sqlite3
from typing import Protocol

from queenbee.adapters.outbound.notifiers import LoggingNotifier, MemoryNotifier
from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.application.ports import IncidentRepository, Notifier


class ComponentFactory(Protocol):
    def repository(self) -> IncidentRepository: ...

    def notifier(self) -> Notifier: ...


class InMemoryFactory:
    """Famille « mémoire » : aucune base, aucun réseau (tests, démo)."""

    def repository(self) -> IncidentRepository:
        return InMemoryIncidentRepository()

    def notifier(self) -> Notifier:
        return MemoryNotifier()


class ProdFactory:
    """Famille « production » : SQLite + journal. On ne mélange jamais avec la famille mémoire."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    def repository(self) -> IncidentRepository:
        return SqliteIncidentRepository(sqlite3.connect(self._db_path))

    def notifier(self) -> Notifier:
        return LoggingNotifier()
