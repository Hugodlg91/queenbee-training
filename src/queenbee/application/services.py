"""Cas d'usage : orchestrent le domaine à travers les ports, reçus par le constructeur."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from uuid import UUID

from queenbee.application.ports import IncidentRepository, Notifier
from queenbee.domain.model import DomainError, Incident, IncidentStatus, Principal, SecurityEvent
from queenbee.domain.rules import Rule

_audit_log = logging.getLogger("queenbee.audit")


class AccessDeniedError(PermissionError):
    """Le principal n'a pas le rôle requis : l'action est refusée, sans effet."""


class DetectionService:
    """Évalue un lot d'événements validés, ouvre un incident par alerte et prévient le SOC."""

    def __init__(
        self, rule: Rule, repository: IncidentRepository, notifiers: Sequence[Notifier]
    ) -> None:
        self._rule = rule
        self._repository = repository
        self._notifiers = tuple(notifiers)

    def ingest(self, events: Iterable[SecurityEvent]) -> list[Incident]:
        created: list[Incident] = []
        for alert in self._rule.evaluate(list(events)):
            incident = Incident(alert)
            self._repository.add(incident)
            for notifier in self._notifiers:
                notifier.notify(alert)
            created.append(incident)
        return created


class IncidentService:
    """Cas d'usage des analystes. Toujours : autoriser -> vérifier -> règle métier -> persister."""

    REQUIRED_ROLE = "analyst"

    def __init__(self, incidents: IncidentRepository) -> None:
        self._incidents = incidents

    def move(self, who: Principal, incident_id: UUID, to: IncidentStatus) -> Incident:
        if not who.has(self.REQUIRED_ROLE):  # 1. autoriser, avant même de lire
            _audit_log.warning("refus : %s veut passer %s en %s", who.user, incident_id, to.value)
            raise AccessDeniedError(who.user)
        incident = self._incidents.get(incident_id)  # 2. vérifier
        if incident is None:
            raise DomainError("incident introuvable")
        incident.transition_to(to)  # 3. règle métier (State)
        self._incidents.save(incident)  # 4. persister
        _audit_log.info("%s a passé %s en %s", who.user, incident.id, to.value)
        return incident
