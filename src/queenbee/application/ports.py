"""Ports : ce dont les cas d'usage ont besoin, sans dire comment (ni sqlite3 ni smtplib)."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from queenbee.domain.model import Alert, Incident


class IncidentReader(Protocol):
    """La partie « lecture » du dépôt : ce que voit un lecteur, rien de plus."""

    def get(self, incident_id: UUID) -> Incident | None: ...

    def list_open(self) -> list[Incident]: ...


class IncidentRepository(IncidentReader, Protocol):
    def add(self, incident: Incident) -> None: ...

    def save(self, incident: Incident) -> None: ...


class Notifier(Protocol):
    def notify(self, alert: Alert) -> None: ...
