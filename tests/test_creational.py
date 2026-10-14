"""Jour 1 — Abstract Factory et Prototype."""

from dataclasses import replace

import pytest

from queenbee.adapters.outbound.notifiers import MemoryNotifier
from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.application.services import DetectionService
from queenbee.domain.model import DomainError, SecurityEvent
from queenbee.domain.rules import BruteForceRule
from queenbee.factories import ComponentFactory, InMemoryFactory, ProdFactory


def test_each_factory_builds_a_consistent_family() -> None:
    assert isinstance(InMemoryFactory().repository(), InMemoryIncidentRepository)
    assert isinstance(InMemoryFactory().notifier(), MemoryNotifier)
    assert isinstance(ProdFactory(":memory:").repository(), SqliteIncidentRepository)


def test_service_runs_with_any_family(five_failures: list[SecurityEvent]) -> None:
    factory: ComponentFactory = InMemoryFactory()
    notifier = factory.notifier()
    DetectionService(BruteForceRule(), factory.repository(), [notifier]).ingest(five_failures)
    assert isinstance(notifier, MemoryNotifier)
    assert len(notifier.received) == 1


def test_prototype_copy_is_revalidated() -> None:
    base = BruteForceRule(threshold=5)
    strict = replace(base, threshold=3)
    assert (base.threshold, strict.threshold) == (5, 3)
    with pytest.raises(DomainError):
        replace(base, threshold=0)
