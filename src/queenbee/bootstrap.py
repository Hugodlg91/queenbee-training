"""Racine de composition : le seul endroit qui crée et relie les objets (plus de Singleton)."""

from __future__ import annotations

from collections.abc import Iterable

from queenbee.application.ports import IncidentRepository
from queenbee.application.services import DetectionService
from queenbee.config import Settings
from queenbee.domain.model import Incident, SecurityEvent
from queenbee.domain.rules import Rule, RuleSet, build_rule
from queenbee.factories import ComponentFactory, ProdFactory


class QueenBee:
    """Facade : un point d'entrée simple devant les cas d'usage."""

    def __init__(self, detection: DetectionService, repository: IncidentRepository) -> None:
        self._detection = detection
        self._repository = repository

    def ingest(self, events: Iterable[SecurityEvent]) -> list[Incident]:
        return self._detection.ingest(events)

    def open_incidents(self) -> list[Incident]:
        return self._repository.list_open()


def build_rules(settings: Settings) -> Rule:
    return RuleSet(
        (
            build_rule({"kind": "brute_force", "threshold": settings.bf_threshold}),
            build_rule({"kind": "port_scan"}),
        )
    )


def build_app(settings: Settings, factory: ComponentFactory | None = None) -> QueenBee:
    factory = factory or ProdFactory(settings.db_path)
    repository = factory.repository()
    detection = DetectionService(build_rules(settings), repository, [factory.notifier()])
    return QueenBee(detection, repository)
