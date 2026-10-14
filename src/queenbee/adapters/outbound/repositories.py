"""Dépôts d'incidents : une implémentation mémoire (tests) et une SQLite (production)."""

from __future__ import annotations

import sqlite3
from uuid import UUID

from queenbee.domain.model import Alert, Incident, IncidentStatus, Severity


class InMemoryIncidentRepository:
    def __init__(self) -> None:
        self._items: dict[UUID, Incident] = {}

    def add(self, incident: Incident) -> None:
        self._items[incident.id] = incident

    def save(self, incident: Incident) -> None:
        self._items[incident.id] = incident

    def get(self, incident_id: UUID) -> Incident | None:
        return self._items.get(incident_id)

    def list_open(self) -> list[Incident]:
        return [i for i in self._items.values() if i.status is not IncidentStatus.CLOSED]


class SqliteIncidentRepository:
    """Toutes les requêtes sont paramétrées (`?`) : une donnée n'est jamais du SQL."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection
        with self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS incident ("
                " id TEXT PRIMARY KEY, rule TEXT NOT NULL, source_ip TEXT NOT NULL,"
                " severity INTEGER NOT NULL, detail TEXT NOT NULL, status TEXT NOT NULL)"
            )

    def add(self, incident: Incident) -> None:
        a = incident.alert
        with self._conn:
            self._conn.execute(
                "INSERT INTO incident (id, rule, source_ip, severity, detail, status)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(incident.id),
                    a.rule,
                    a.source_ip,
                    int(a.severity),
                    a.detail,
                    incident.status.value,
                ),
            )

    def save(self, incident: Incident) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE incident SET status = ? WHERE id = ?",
                (incident.status.value, str(incident.id)),
            )

    def get(self, incident_id: UUID) -> Incident | None:
        row = self._conn.execute(
            "SELECT id, rule, source_ip, severity, detail, status FROM incident WHERE id = ?",
            (str(incident_id),),
        ).fetchone()
        return None if row is None else self._to_incident(row)

    def list_open(self) -> list[Incident]:
        rows = self._conn.execute(
            "SELECT id, rule, source_ip, severity, detail, status FROM incident"
            " WHERE status != ? ORDER BY rowid",
            (IncidentStatus.CLOSED.value,),
        ).fetchall()
        return [self._to_incident(r) for r in rows]

    @staticmethod
    def _to_incident(row: tuple[str, str, str, int, str, str]) -> Incident:
        # Relire = revalider : une ligne altérée en base lève DomainError au lieu de passer.
        incident_id, rule, ip, severity, detail, status = row
        return Incident(
            Alert(rule, ip, Severity(severity), detail),
            id=UUID(incident_id),
            status=IncidentStatus(status),
        )
