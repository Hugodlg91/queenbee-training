"""Jour 2 — cas d'usage testés avec des doublures (aucune base, aucun réseau)."""

import sqlite3
from uuid import uuid4

import pytest

from queenbee.adapters.outbound.notifiers import AuditedNotifier, RateLimitedNotifier
from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.adapters.outbound.response import BlockIpCommand, CommandHistory, InMemoryFirewall
from queenbee.application.access import IncidentReadProxy
from queenbee.application.services import AccessDeniedError, DetectionService, IncidentService
from queenbee.domain.model import Alert, DomainError, IncidentStatus, Principal, SecurityEvent
from queenbee.domain.rules import BruteForceRule
from tests.conftest import ev

ANALYST = Principal("alice", frozenset({"analyst"}))
INTRUDER = Principal("mallory", frozenset({"viewer"}))


class SpyNotifier:
    def __init__(self) -> None:
        self.received: list[Alert] = []

    def notify(self, alert: Alert) -> None:
        self.received.append(alert)


def test_detection_creates_incident_and_notifies(five_failures: list[SecurityEvent]) -> None:
    repo, spy = InMemoryIncidentRepository(), SpyNotifier()
    created = DetectionService(BruteForceRule(), repo, [spy]).ingest(five_failures)
    assert len(created) == 1
    assert repo.list_open() == created
    assert spy.received[0].source_ip == "10.0.0.66"


def test_abuse_viewer_cannot_close_incident(five_failures: list[SecurityEvent]) -> None:
    repo = InMemoryIncidentRepository()
    [inc] = DetectionService(BruteForceRule(), repo, []).ingest(five_failures)
    with pytest.raises(AccessDeniedError):
        IncidentService(repo).move(INTRUDER, inc.id, IncidentStatus.TRIAGED)
    assert inc.status is IncidentStatus.OPEN


def test_analyst_moves_incident(five_failures: list[SecurityEvent]) -> None:
    repo = InMemoryIncidentRepository()
    [inc] = DetectionService(BruteForceRule(), repo, []).ingest(five_failures)
    IncidentService(repo).move(ANALYST, inc.id, IncidentStatus.TRIAGED)
    with pytest.raises(DomainError):
        IncidentService(repo).move(ANALYST, uuid4(), IncidentStatus.TRIAGED)


def test_proxy_blocks_principal_without_role() -> None:
    nobody = Principal("guest", frozenset())
    with pytest.raises(AccessDeniedError):
        IncidentReadProxy(InMemoryIncidentRepository(), nobody).list_open()


def test_abuse_rate_limiter_absorbs_alert_flood() -> None:
    spy, now = SpyNotifier(), [0.0]
    limited = RateLimitedNotifier(spy, max_per_window=3, window_s=60, clock=lambda: now[0])
    alert = Alert("r", "10.0.0.1", BruteForceRule().evaluate([ev()] * 5)[0].severity, "x")
    for _ in range(1_000):
        limited.notify(alert)
    assert len(spy.received) == 3
    assert limited.dropped == 997
    now[0] = 61.0
    limited.notify(alert)
    assert len(spy.received) == 4


def test_audit_decorator_logs(caplog: pytest.LogCaptureFixture) -> None:
    spy = SpyNotifier()
    caplog.set_level("INFO", logger="queenbee.audit")
    AuditedNotifier(spy).notify(Alert("brute_force", "10.0.0.1", 3, "x"))  # type: ignore[arg-type]
    assert "brute_force" in caplog.text
    assert len(spy.received) == 1


def test_sqlite_repo_resists_injection(five_failures: list[SecurityEvent]) -> None:
    repo = SqliteIncidentRepository(sqlite3.connect(":memory:"))
    [inc] = DetectionService(BruteForceRule(), repo, []).ingest(five_failures)
    assert repo.get(inc.id) == inc
    assert len(repo.list_open()) == 1


def test_command_undo() -> None:
    fw, history = InMemoryFirewall(), CommandHistory()
    history.run(BlockIpCommand(fw, "10.0.0.66"))
    assert "10.0.0.66" in fw.blocked
    history.undo_last()
    assert fw.blocked == set()
    with pytest.raises(ValueError, match="does not appear"):
        BlockIpCommand(fw, "10.0.0.1; iptables -F")
