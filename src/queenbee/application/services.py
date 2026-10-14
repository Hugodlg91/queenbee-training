"""Cas d'usage : orchestrent le domaine à travers les ports, reçus par le constructeur."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from queenbee.application.ports import IncidentRepository, Notifier
from queenbee.domain.model import Incident, SecurityEvent
from queenbee.domain.rules import Rule


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
