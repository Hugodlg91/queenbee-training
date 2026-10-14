"""Jour 1 — tests d'abus du groupe : créer sous contrôle, ne jamais faire fuir le secret."""

import logging
import sqlite3
from dataclasses import replace
from uuid import uuid4

import pytest

from queenbee.adapters.outbound.notifiers import LoggingNotifier, MemoryNotifier
from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.bootstrap import build_app
from queenbee.config import ConfigError, Settings, SettingsBuilder, settings_from_env
from queenbee.domain.model import Alert, DomainError, Incident, IncidentStatus, Severity
from queenbee.domain.rules import BruteForceRule, PortScanRule, RuleSet, build_rule
from queenbee.factories import InMemoryFactory, ProdFactory
from tests.conftest import ev

KEY = bytes(range(32))


# --- Factory : seuls les noms enregistrés, seuls des entiers ---------------------------------


@pytest.mark.parametrize(
    "spec",
    [
        {"kind": "BruteForceRule"},  # nom de classe, pas nom enregistré
        {"kind": "__class__"},
        {"kind": "os.system"},
        {"kind": 1},
        {"kind": "brute_force", "threshold": True},
        {"kind": "brute_force", "threshold": "5"},
        {"kind": "brute_force", "threshold": 5.0},
        {"kind": "brute_force", "threshold": -1},
        {"kind": "brute_force", "threshold": 10**9},
        {"kind": "brute_force", "threshold": 5, "module": "os"},  # clé en trop
    ],
)
def test_abuse_factory_rejects_hostile_spec(spec: dict[str, object]) -> None:
    with pytest.raises(DomainError):
        build_rule(spec)


def test_factory_builds_registered_rules() -> None:
    assert build_rule({"kind": "brute_force", "threshold": 3}) == BruteForceRule(3)
    assert build_rule({"kind": "port_scan"}) == PortScanRule()


def test_prototype_copy_is_independent_and_revalidated() -> None:
    base = PortScanRule(threshold=20)
    assert replace(base, threshold=5).threshold == 5
    with pytest.raises(DomainError):
        replace(base, threshold=True)  # type: ignore[arg-type]


def test_empty_ruleset_rejected() -> None:
    with pytest.raises(DomainError):
        RuleSet(())


# --- Builder : validé à la fin, figé, secret invisible ---------------------------------------


def test_secret_never_in_repr_or_str() -> None:
    settings = SettingsBuilder().hmac_key(KEY).db_path(":memory:").bf_threshold(3).build()
    for text in (repr(settings), str(settings), f"{settings}"):
        assert KEY.hex() not in text
        assert repr(KEY) not in text
    assert (settings.db_path, settings.bf_threshold) == (":memory:", 3)


def test_settings_are_frozen() -> None:
    settings = SettingsBuilder().hmac_key(KEY).build()
    with pytest.raises(AttributeError):
        settings.hmac_key = b"x" * 32  # type: ignore[misc]


@pytest.mark.parametrize(
    "builder",
    [
        SettingsBuilder(),  # pas de clé
        SettingsBuilder().hmac_key(b"court"),
        SettingsBuilder().hmac_key(KEY).bf_threshold(True),
        SettingsBuilder().hmac_key(KEY).bf_threshold(0),
        SettingsBuilder().hmac_key(KEY).db_path(""),
        SettingsBuilder().hmac_key(KEY).db_path("a\x00b"),
    ],
)
def test_abuse_builder_refuses_invalid_config(builder: SettingsBuilder) -> None:
    with pytest.raises(ConfigError):
        builder.build()


def test_settings_cannot_bypass_builder_validation() -> None:
    with pytest.raises(ConfigError):
        Settings(b"")
    with pytest.raises(ConfigError):
        Settings(KEY, bf_threshold="5")  # type: ignore[arg-type]


def test_settings_from_env_reads_all_values() -> None:
    env = {"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_DB": "x.db", "QUEENBEE_BF_THRESHOLD": "7"}
    settings = settings_from_env(env)
    assert (settings.hmac_key, settings.db_path, settings.bf_threshold) == (KEY, "x.db", 7)


def test_settings_from_env_defaults_to_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QUEENBEE_AGENT_KEY", KEY.hex())
    assert settings_from_env().hmac_key == KEY


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"QUEENBEE_AGENT_KEY": "zz" * 32},  # pas de l'hexadécimal
        {"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_BF_THRESHOLD": "True"},
        {"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_BF_THRESHOLD": "1_000"},
        {"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_BF_THRESHOLD": "-5"},
    ],
)
def test_abuse_env_refuses_to_start(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        settings_from_env(env)


def test_invalid_secret_is_not_echoed_in_error() -> None:
    secret = "zz" + KEY.hex()
    with pytest.raises(ConfigError) as info:
        settings_from_env({"QUEENBEE_AGENT_KEY": secret})
    assert secret not in str(info.value)
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__


# --- Fabrique abstraite et racine de composition ---------------------------------------------


def test_prod_family_uses_logging_notifier(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="queenbee.alerts")
    notifier = ProdFactory(":memory:").notifier()
    assert isinstance(notifier, LoggingNotifier)
    notifier.notify(Alert("brute_force", "10.0.0.66", Severity.HIGH, "5 échecs"))
    assert "brute_force" in caplog.text
    assert "10.0.0.66" in caplog.text


def test_build_app_wires_everything_without_global_state() -> None:
    settings = SettingsBuilder().hmac_key(KEY).bf_threshold(3).build()
    app = build_app(settings, InMemoryFactory())
    other = build_app(settings, InMemoryFactory())
    events = [ev() for _ in range(3)] + [ev(ip="10.0.0.7", action="port_probe")] * 20
    assert {i.alert.rule for i in app.ingest(events)} == {"brute_force", "port_scan"}
    assert len(app.open_incidents()) == 2
    assert other.open_incidents() == []  # aucune fuite d'état entre deux applications


def test_build_app_defaults_to_production_family() -> None:
    app = build_app(SettingsBuilder().hmac_key(KEY).db_path(":memory:").build())
    assert len(app.ingest([ev()] * 5)) == 1
    assert len(app.open_incidents()) == 1


# --- Dépôts : SQL paramétré, relecture revalidée ---------------------------------------------


def test_sqlite_stores_hostile_text_verbatim() -> None:
    conn = sqlite3.connect(":memory:")
    repo = SqliteIncidentRepository(conn)
    hostile = "x'); DROP TABLE incident;--"
    inc = Incident(Alert("brute_force", "10.0.0.1", Severity.HIGH, hostile))
    repo.add(inc)
    stored = repo.get(inc.id)
    assert stored is not None
    assert stored.alert.detail == hostile
    assert conn.execute("SELECT count(*) FROM incident").fetchone() == (1,)


@pytest.mark.parametrize(
    "repo_factory", [InMemoryIncidentRepository, ProdFactory(":memory:").repository]
)
def test_repository_contract(repo_factory: type[InMemoryIncidentRepository]) -> None:
    repo = repo_factory()
    inc = Incident(Alert("brute_force", "10.0.0.1", Severity.HIGH, "x"))
    repo.add(inc)
    assert repo.get(uuid4()) is None
    inc.transition_to(IncidentStatus.TRIAGED)
    inc.transition_to(IncidentStatus.CLOSED)
    repo.save(inc)
    assert repo.get(inc.id) == inc
    assert repo.list_open() == []


def test_tampered_row_is_rejected_on_read() -> None:
    conn = sqlite3.connect(":memory:")
    repo = SqliteIncidentRepository(conn)
    inc = Incident(Alert("brute_force", "10.0.0.1", Severity.HIGH, "x"))
    repo.add(inc)
    conn.execute("UPDATE incident SET source_ip = '10.0.0.1; rm -rf /'")
    with pytest.raises(DomainError):
        repo.get(inc.id)


# --- Domaine : invariants supplémentaires ----------------------------------------------------


@pytest.mark.parametrize(
    ("rule", "ip", "severity", "detail"),
    [
        ("Brute Force", "10.0.0.1", Severity.HIGH, "x"),
        ("brute_force", "localhost", Severity.HIGH, "x"),
        ("brute_force", "10.0.0.1", True, "x"),
        ("brute_force", "10.0.0.1", 99, "x"),
        ("brute_force", "10.0.0.1", Severity.HIGH, "x" * 1_000),
    ],
)
def test_invalid_alert_cannot_exist(rule: str, ip: str, severity: Severity, detail: str) -> None:
    with pytest.raises(DomainError):
        Alert(rule, ip, severity, detail)


def test_incident_identity_and_closed_is_final() -> None:
    alert = Alert("r", "10.0.0.1", Severity.LOW, "x")
    a, b = Incident(alert), Incident(alert)
    assert a != b
    assert a != "pas un incident"
    assert len({a, a}) == 1
    assert "status=open" in repr(a)
    with pytest.raises(DomainError):
        Incident("pas une alerte")  # type: ignore[arg-type]
    a.transition_to(IncidentStatus.TRIAGED)
    a.transition_to(IncidentStatus.CONTAINED)
    a.transition_to(IncidentStatus.CLOSED)
    with pytest.raises(DomainError):
        a.transition_to(IncidentStatus.OPEN)


def test_memory_notifier_records() -> None:
    notifier = MemoryNotifier()
    alert = Alert("r", "10.0.0.1", 2, "x")  # type: ignore[arg-type]
    notifier.notify(alert)
    assert notifier.received[0].severity is Severity.MEDIUM
