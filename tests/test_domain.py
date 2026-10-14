"""Jour 1 — objets immuables, validation à la construction, Strategy/Composite/Factory."""

from dataclasses import FrozenInstanceError
from datetime import datetime

import pytest

from queenbee.domain.model import (
    Alert,
    DomainError,
    Incident,
    IncidentStatus,
    SecurityEvent,
    Severity,
)
from queenbee.domain.rules import BruteForceRule, PortScanRule, RuleSet, build_rule
from tests.conftest import T0, ev


def test_event_is_immutable() -> None:
    e = ev()
    with pytest.raises(FrozenInstanceError):
        e.source_ip = "1.2.3.4"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("ip", "user", "action"),
    [
        ("999.1.1.1", "root", "login_failed"),  # IP impossible
        ("10.0.0.1", "root'; DROP TABLE x;--", "login_failed"),  # injection dans le nom
        ("10.0.0.1", "a" * 200, "login_failed"),  # longueur abusive
        ("10.0.0.1", "root", "rm -rf"),  # action hors allowlist
    ],
)
def test_invalid_event_cannot_exist(ip: str, user: str, action: str) -> None:
    with pytest.raises(DomainError):
        SecurityEvent(ip, user, action, T0)


def test_naive_timestamp_rejected() -> None:
    with pytest.raises(DomainError):
        SecurityEvent("10.0.0.1", "root", "login_ok", datetime(2026, 10, 14))


def test_brute_force_threshold(five_failures: list[SecurityEvent]) -> None:
    assert BruteForceRule(5).evaluate(five_failures)[0].severity is Severity.HIGH
    assert BruteForceRule(6).evaluate(five_failures) == []


def test_composite_ruleset() -> None:
    events = [ev() for _ in range(5)] + [ev(ip="10.0.0.7", action="port_probe")] * 20
    rules = {a.rule for a in RuleSet((BruteForceRule(), PortScanRule())).evaluate(events)}
    assert rules == {"brute_force", "port_scan"}


def test_factory_rejects_unknown_rule() -> None:
    with pytest.raises(DomainError):
        build_rule({"kind": "__import__('os')", "threshold": 1})


def test_factory_rejects_bool_threshold() -> None:
    with pytest.raises(DomainError):
        build_rule({"kind": "brute_force", "threshold": True})


def test_state_forbids_skipping_triage() -> None:
    inc = Incident(Alert("r", "10.0.0.1", Severity.LOW, "x"))
    with pytest.raises(DomainError):
        inc.transition_to(IncidentStatus.CLOSED)
    inc.transition_to(IncidentStatus.TRIAGED)
    inc.transition_to(IncidentStatus.CLOSED)
    assert inc.status is IncidentStatus.CLOSED
