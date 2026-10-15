"""Jour 2 · A1 — cinq patterns défensifs, un test d'abus chacun (refus + aucun effet de bord)."""

import logging

import pytest

from queenbee.adapters.inbound.log_parser import MAX_LINE_LENGTH, parse_sshd_line
from queenbee.adapters.outbound.notifiers import AlertBus, AuditedNotifier, RateLimitedNotifier
from queenbee.adapters.outbound.repositories import InMemoryIncidentRepository
from queenbee.adapters.outbound.response import BlockIpCommand, CommandHistory, InMemoryFirewall
from queenbee.application.access import IncidentReadProxy
from queenbee.application.services import AccessDeniedError, DetectionService
from queenbee.domain.model import (
    Alert,
    DomainError,
    Incident,
    IncidentStatus,
    Principal,
    SecurityEvent,
    Severity,
)
from queenbee.domain.rules import BruteForceRule

ALERT = Alert("brute_force", "10.0.0.66", Severity.HIGH, "5 échecs")
VIEWER = Principal("bob", frozenset({"viewer"}))
GUEST = Principal("guest", frozenset())
GOOD = "2026-10-14T09:00:00+02:00 sshd: Failed password for root from 10.0.0.66"


class Spy:
    def __init__(self) -> None:
        self.received: list[Alert] = []

    def notify(self, alert: Alert) -> None:
        self.received.append(alert)


class Broken:
    def notify(self, alert: Alert) -> None:
        raise ConnectionError("SMTP injoignable")


def _repo_with_incident(events: list[SecurityEvent]) -> tuple[InMemoryIncidentRepository, Incident]:
    repo = InMemoryIncidentRepository()
    [incident] = DetectionService(BruteForceRule(), repo, []).ingest(events)
    return repo, incident


# --- 1. Proxy (C) : la lecture des incidents ------------------------------------------------


def test_abuse_proxy_refuses_principal_without_role(five_failures: list[SecurityEvent]) -> None:
    repo, incident = _repo_with_incident(five_failures)
    proxy = IncidentReadProxy(repo, GUEST)
    with pytest.raises(AccessDeniedError):
        proxy.list_open()
    with pytest.raises(AccessDeniedError):
        proxy.get(incident.id)
    assert proxy.denied == 2  # un rejet est toujours compté


def test_abuse_reader_cannot_modify_what_it_reads(five_failures: list[SecurityEvent]) -> None:
    repo, incident = _repo_with_incident(five_failures)
    [seen] = IncidentReadProxy(repo, VIEWER).list_open()
    seen.transition_to(IncidentStatus.TRIAGED)  # le lecteur tente de modifier sa copie
    assert incident.status is IncidentStatus.OPEN  # le stockage n'a pas bougé
    assert repo.list_open()[0].status is IncidentStatus.OPEN
    copy = IncidentReadProxy(repo, VIEWER).get(incident.id)
    assert copy == incident
    assert copy is not incident


# --- 2. Décorateurs (D · P) : le SOC contre l'inondation, et la trace -------------------------


def test_abuse_alert_flood_is_absorbed_and_counted() -> None:
    spy, now = Spy(), [0.0]
    limited = RateLimitedNotifier(spy, max_per_window=3, window_s=60, clock=lambda: now[0])
    for _ in range(1_000):
        limited.notify(ALERT)
    assert (len(spy.received), limited.dropped) == (3, 997)
    now[0] = 59.9  # toujours dans la fenêtre : toujours bloqué
    limited.notify(ALERT)
    assert (len(spy.received), limited.dropped) == (3, 998)


@pytest.mark.parametrize("bad", [{"max_per_window": 0}, {"max_per_window": True}, {"window_s": 0}])
def test_abuse_rate_limiter_cannot_be_disabled(bad: dict[str, float]) -> None:
    with pytest.raises(ValueError):
        RateLimitedNotifier(Spy(), **bad)  # type: ignore[arg-type]


def test_audit_trace_even_when_rate_limited(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="queenbee.audit")
    spy = Spy()
    chain = AuditedNotifier(RateLimitedNotifier(spy, max_per_window=1, clock=lambda: 0.0))
    chain.notify(ALERT)
    chain.notify(ALERT)
    assert caplog.text.count("brute_force sur 10.0.0.66") == 2
    assert len(spy.received) == 1


# --- 3. Adaptateur (I) : ligne de journal -> événement ---------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        GOOD + " " * MAX_LINE_LENGTH,  # ligne énorme : refusée avant la regex
        GOOD.replace("root", "root from 6.6.6.6"),  # attribution déplacée
        GOOD.replace("10.0.0.66", "10.0.0.66\n2026-10-14T09:00:01+02:00 sshd: forged"),
        GOOD.replace("+02:00", ""),  # horodatage sans fuseau
        GOOD.replace("2026-10-14", "2026-13-45"),  # date impossible
        None,
    ],
)
def test_abuse_trapped_log_line_rejected(line: str) -> None:
    with pytest.raises(DomainError):
        parse_sshd_line(line)


def test_adapter_accepts_real_sshd_variants() -> None:
    event = parse_sshd_line(
        "2026-10-14T09:00:00+00:00 sshd[812]: Failed password for invalid user admin"
        " from 2001:db8::7 port 51234 ssh2"
    )
    assert (event.username, event.source_ip, event.action) == (
        "admin",
        "2001:db8::7",
        "login_failed",
    )
    assert parse_sshd_line(GOOD.replace("Failed", "Accepted")).action == "login_ok"


# --- 4. Observateur (D) : un abonné en panne ne bloque pas les autres (bonus) -----------------


def test_abuse_broken_subscriber_does_not_block_others(caplog: pytest.LogCaptureFixture) -> None:
    bus, first, last = AlertBus(), Spy(), Spy()
    for subscriber in (first, Broken(), last):
        bus.subscribe(subscriber)
    bus.notify(ALERT)
    assert first.received == last.received == [ALERT]
    assert bus.failures == 1
    assert "Broken" in caplog.text
    bus.unsubscribe(first)
    bus.notify(ALERT)
    assert (len(first.received), len(last.received)) == (1, 2)


# --- 5. Commande et État (I · P) : blocage d'IP et cycle de vie ------------------------------


@pytest.mark.parametrize(
    "target",
    ["10.0.0.1; iptables -F", "$(reboot)", "10.0.0.1 -j ACCEPT", "127.0.0.1", "::", ""],
)
def test_abuse_trapped_ip_never_reaches_firewall(target: str) -> None:
    firewall, history = InMemoryFirewall(), CommandHistory()
    with pytest.raises(ValueError):
        history.run(BlockIpCommand(firewall, target))
    assert firewall.blocked == set()


def test_command_is_traced_and_undoable(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="queenbee.audit")
    firewall, history = InMemoryFirewall(), CommandHistory()
    history.run(BlockIpCommand(firewall, "203.0.113.9"))
    assert firewall.blocked == {"203.0.113.9"}
    history.undo_last()
    assert firewall.blocked == set()
    assert "exécutée : BlockIpCommand(203.0.113.9)" in caplog.text
    assert "annulée : BlockIpCommand(203.0.113.9)" in caplog.text
    with pytest.raises(DomainError):
        history.undo_last()


@pytest.mark.parametrize(
    ("path", "forbidden"),
    [
        ((), IncidentStatus.CLOSED),
        ((), IncidentStatus.CONTAINED),
        ((IncidentStatus.TRIAGED,), IncidentStatus.OPEN),
        ((IncidentStatus.TRIAGED, IncidentStatus.CLOSED), IncidentStatus.TRIAGED),
    ],
)
def test_abuse_forbidden_transition_refused(
    path: tuple[IncidentStatus, ...], forbidden: IncidentStatus
) -> None:
    incident = Incident(ALERT)
    for step in path:
        incident.transition_to(step)
    before = incident.status
    with pytest.raises(DomainError):
        incident.transition_to(forbidden)
    assert incident.status is before


def test_principal_is_validated() -> None:
    assert VIEWER.has("viewer")
    assert not VIEWER.has("analyst")
    with pytest.raises(DomainError):
        Principal("eve", frozenset({"root"}))  # rôle inconnu
    with pytest.raises(DomainError):
        Principal("eve'; --", frozenset())
    with pytest.raises(DomainError):
        Principal("eve", {"viewer"})  # type: ignore[arg-type]  # set modifiable
