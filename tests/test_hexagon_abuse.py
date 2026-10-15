"""Jour 2 · A3 — entrées malveillantes aux ports de l'hexagone, sans base ni réseau réels."""

import contextlib
import json
from uuid import UUID

import pytest
from hypothesis import given
from hypothesis import strategies as st

from queenbee.adapters.inbound.agent_api import (
    MAX_BODY_BYTES,
    UnauthenticatedError,
    parse_agent_message,
    sign,
)
from queenbee.adapters.inbound.threat_feed import ThreatFeedTranslator
from queenbee.adapters.outbound.repositories import InMemoryIncidentRepository
from queenbee.application.services import AccessDeniedError, DetectionService, IncidentService
from queenbee.bootstrap import build_app
from queenbee.config import SettingsBuilder
from queenbee.domain.model import DomainError, Incident, IncidentStatus, Principal, SecurityEvent
from queenbee.domain.rules import BruteForceRule
from queenbee.factories import InMemoryFactory

KEY = bytes(range(32))
GOOD = {
    "source_ip": "10.0.0.66",
    "username": "root",
    "action": "login_failed",
    "timestamp": "2026-10-14T09:00:00+00:00",
}
ANALYST = Principal("alice", frozenset({"analyst"}))
VIEWER = Principal("bob", frozenset({"viewer"}))


def signed(body: bytes) -> tuple[bytes, str]:
    return body, sign(body, KEY)


class CountingRepository(InMemoryIncidentRepository):
    def __init__(self) -> None:
        super().__init__()
        self.reads = self.saves = 0

    def get(self, incident_id: UUID) -> Incident | None:
        self.reads += 1
        return super().get(incident_id)

    def save(self, incident: Incident) -> None:
        self.saves += 1
        super().save(incident)


# --- Entrée agents : signature, taille, schéma -----------------------------------------------


@pytest.mark.parametrize(
    "signature",
    [
        "",
        "0" * 64,
        sign(json.dumps(GOOD).encode(), KEY).upper(),  # bonne valeur, mauvaise forme
        sign(json.dumps(GOOD).encode(), KEY)[:-1] + "é",  # non ASCII
        sign(
            json.dumps(GOOD | {"username": "admin"}).encode(), KEY
        ),  # signature d'un autre message
    ],
)
def test_abuse_forged_or_replayed_signature_rejected(signature: str) -> None:
    with pytest.raises(UnauthenticatedError):
        parse_agent_message(json.dumps(GOOD).encode(), signature, KEY)


def test_abuse_tampered_body_rejected() -> None:
    body, signature = signed(json.dumps(GOOD).encode())
    tampered = body.replace(b"10.0.0.66", b"10.0.0.99")  # altéré en route (T sur TB1)
    with pytest.raises(UnauthenticatedError):
        parse_agent_message(tampered, signature, KEY)


@pytest.mark.parametrize(
    "body",
    [
        json.dumps(GOOD | {"is_admin": "true"}).encode(),  # champ en trop
        json.dumps({k: v for k, v in GOOD.items() if k != "action"}).encode(),  # champ manquant
        json.dumps(GOOD | {"username": ["root"]}).encode(),  # mauvais type
        b'{"source_ip": "10.0.0.66", "source_ip": "1.1.1.1", "username": "root",'
        b' "action": "login_failed", "timestamp": "2026-10-14T09:00:00+00:00"}',  # clé dupliquée
        json.dumps(GOOD).replace('"root"', "NaN").encode(),  # constante non standard
        b"\xff\xfe" + json.dumps(GOOD).encode(),  # pas de l'UTF-8
        b"[1, 2, 3]",
        json.dumps(GOOD | {"timestamp": "hier"}).encode(),
        json.dumps(GOOD | {"username": "root'; DROP TABLE incident;--"}).encode(),
    ],
)
def test_abuse_signed_but_malformed_message_rejected(body: bytes) -> None:
    # Même un agent compromis, qui possède la vraie clé, ne fait pas entrer un objet invalide.
    with pytest.raises(DomainError):
        parse_agent_message(*signed(body), KEY)


def test_abuse_oversized_body_rejected_before_hmac() -> None:
    body = b" " * (MAX_BODY_BYTES + 1)
    with pytest.raises(DomainError):
        parse_agent_message(body, "pas même une signature", KEY)


def test_abuse_short_key_refused() -> None:
    with pytest.raises(ValueError):
        sign(b"x", b"short")


@given(st.binary(max_size=600))
def test_agent_api_never_crashes_on_signed_garbage(body: bytes) -> None:
    """Propriété : pour tout message bien signé, soit un événement valide, soit DomainError."""
    with contextlib.suppress(DomainError):
        assert isinstance(parse_agent_message(*signed(body), KEY), SecurityEvent)


@given(st.binary(max_size=600), st.text(max_size=70))
def test_agent_api_rejects_any_unsigned_input(body: bytes, signature: str) -> None:
    with contextlib.suppress(DomainError, UnauthenticatedError):
        parse_agent_message(body, signature, KEY)
        assert signature == sign(body, KEY)  # n'est accepté que si la signature est la vraie


# --- Cas d'usage : l'ordre autoriser -> vérifier -> métier -> persister ----------------------


def test_abuse_unauthorized_move_touches_nothing(five_failures: list[SecurityEvent]) -> None:
    repo = CountingRepository()
    [incident] = DetectionService(BruteForceRule(), repo, []).ingest(five_failures)
    with pytest.raises(AccessDeniedError):
        IncidentService(repo).move(VIEWER, incident.id, IncidentStatus.TRIAGED)
    assert (repo.reads, repo.saves) == (0, 0)  # refusé AVANT même de lire
    assert incident.status is IncidentStatus.OPEN


def test_abuse_forbidden_transition_is_not_persisted(five_failures: list[SecurityEvent]) -> None:
    repo = CountingRepository()
    [incident] = DetectionService(BruteForceRule(), repo, []).ingest(five_failures)
    with pytest.raises(DomainError):
        IncidentService(repo).move(ANALYST, incident.id, IncidentStatus.CLOSED)
    assert repo.saves == 0
    assert IncidentService(repo).move(ANALYST, incident.id, IncidentStatus.TRIAGED).status is (
        IncidentStatus.TRIAGED
    )
    assert repo.saves == 1


# --- Couche anti-corruption ------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        {"indicator": "203.0.113.9", "risk_level": "extreme"},
        {"indicator": None, "risk_level": "high"},
        {"indicator": "203.0.113.9", "risk_level": 80},
        {"indicator": "203.0.113.9/24", "risk_level": "low"},
        "203.0.113.9",
    ],
)
def test_abuse_threat_feed_garbage_rejected(raw: object) -> None:
    with pytest.raises(DomainError):
        ThreatFeedTranslator().translate(raw)  # type: ignore[arg-type]


def test_threat_feed_ignores_vendor_noise() -> None:
    raw = {"indicator": "2001:db8::1", "risk_level": "CRITICAL", "vendor_tag": "<script>"}
    indicator = ThreatFeedTranslator().translate(raw)
    assert (indicator.ip, indicator.score) == ("2001:db8::1", 100)


# --- Façade : de bout en bout, sans base réelle ----------------------------------------------


def test_facade_counts_every_rejected_line() -> None:
    app = build_app(SettingsBuilder().hmac_key(KEY).build(), InMemoryFactory())
    good = "2026-10-14T09:00:00+02:00 sshd: Failed password for root from 10.0.0.66"
    hostile = [good + " OR 1=1", "A" * 10_000, "\x1b[2J", good.replace("+02:00", "")]
    assert len(app.ingest_lines([good] * 5 + hostile)) == 1
    assert app.rejected == len(hostile)
    assert len(app.open_incidents()) == 1
