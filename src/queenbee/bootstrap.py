"""Racine de composition : le seul endroit qui crée et relie les objets (plus de Singleton)."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from queenbee.adapters.inbound.log_parser import parse_sshd_line
from queenbee.adapters.outbound.notifiers import AuditedNotifier, RateLimitedNotifier
from queenbee.application.ports import IncidentRepository
from queenbee.application.services import DetectionService
from queenbee.config import Settings
from queenbee.domain.model import DomainError, Incident, SecurityEvent
from queenbee.domain.rules import Rule, RuleSet, build_rule
from queenbee.factories import ComponentFactory, ProdFactory

LineParser = Callable[[str], SecurityEvent]


class QueenBee:
    """Facade : une seule porte d'entrée ; les lignes rejetées sont comptées."""

    def __init__(
        self,
        detection: DetectionService,
        repository: IncidentRepository,
        parser: LineParser = parse_sshd_line,
    ) -> None:
        self._detection = detection
        self._repository = repository
        self._parser = parser
        self.rejected = 0

    def ingest(self, events: Iterable[SecurityEvent]) -> list[Incident]:
        return self._detection.ingest(events)

    def ingest_lines(self, lines: Iterable[str]) -> list[Incident]:
        events: list[SecurityEvent] = []
        for line in lines:
            try:
                events.append(self._parser(line))
            except DomainError:
                self.rejected += 1  # une ligne piégée n'arrête jamais l'ingestion
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
    # Chaque alerte est tracée (Preuve), puis limitée en débit avant le SOC (Disponibilité).
    notifier = AuditedNotifier(RateLimitedNotifier(factory.notifier()))
    detection = DetectionService(build_rules(settings), repository, [notifier])
    return QueenBee(detection, repository)
