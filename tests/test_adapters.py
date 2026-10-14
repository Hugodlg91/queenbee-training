"""Jour 2/3 — entrées malveillantes aux ports d'entrée + test par propriétés (Hypothesis)."""

import contextlib
import json
import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from queenbee.adapters.inbound.agent_api import UnauthenticatedError, parse_agent_message, sign
from queenbee.adapters.inbound.log_parser import parse_sshd_line
from queenbee.adapters.inbound.threat_feed import ThreatFeedTranslator
from queenbee.bootstrap import build_app
from queenbee.config import ConfigError, SettingsBuilder, settings_from_env
from queenbee.domain.model import DomainError

KEY = bytes(range(32))
GOOD = "2026-10-14T09:00:00+02:00 sshd: Failed password for root from 10.0.0.66"


def test_parse_valid_line() -> None:
    e = parse_sshd_line(GOOD)
    assert (e.source_ip, e.username, e.action) == ("10.0.0.66", "root", "login_failed")


@pytest.mark.parametrize(
    "line",
    [
        GOOD.replace("10.0.0.66", "10.0.0.66 OR 1=1"),
        GOOD.replace("root", "<script>alert(1)</script>"),
        GOOD + "A" * 10_000,
        "",
        "\x00\x00\x00",
    ],
)
def test_malicious_lines_rejected(line: str) -> None:
    with pytest.raises(DomainError):
        parse_sshd_line(line)


@given(st.text(max_size=600))
def test_parser_never_crashes_unexpectedly(line: str) -> None:
    """Propriété : quelle que soit l'entrée, soit un événement valide, soit DomainError."""
    with contextlib.suppress(DomainError):
        parse_sshd_line(line)


def test_parser_is_fast_on_adversarial_input() -> None:
    start = time.perf_counter()
    for _ in range(1_000):
        with pytest.raises(DomainError):
            parse_sshd_line("2026-10-14T09:00:00+02:00 sshd: " + "a " * 200)
    assert time.perf_counter() - start < 1.0


def _msg(**over: str) -> bytes:
    data = {
        "source_ip": "10.0.0.66",
        "username": "root",
        "action": "login_failed",
        "timestamp": "2026-10-14T09:00:00+00:00",
    } | over
    return json.dumps(data).encode()


def test_agent_message_authenticated() -> None:
    body = _msg()
    assert parse_agent_message(body, sign(body, KEY), KEY).username == "root"


def test_abuse_forged_signature_rejected() -> None:
    body = _msg()
    with pytest.raises(UnauthenticatedError):
        parse_agent_message(body, sign(body, b"x" * 32), KEY)


def test_abuse_extra_field_rejected() -> None:
    body = _msg(is_admin="true")
    with pytest.raises(DomainError):
        parse_agent_message(body, sign(body, KEY), KEY)


def test_secret_never_printed() -> None:
    s = SettingsBuilder().hmac_key(KEY).build()
    assert KEY.hex() not in repr(s)


def test_missing_secret_refuses_to_start() -> None:
    with pytest.raises(ConfigError):
        settings_from_env({})
    with pytest.raises(ConfigError):
        settings_from_env({"QUEENBEE_AGENT_KEY": "00"})  # clé trop courte


def test_end_to_end_facade() -> None:
    app = build_app(settings_from_env({"QUEENBEE_AGENT_KEY": KEY.hex()}))
    incidents = app.ingest_lines([GOOD] * 5 + ["garbage"])
    assert len(incidents) == 1
    assert app.rejected == 1


def test_anti_corruption_layer_translates_and_rejects() -> None:
    acl = ThreatFeedTranslator()
    assert acl.translate({"indicator": "203.0.113.9", "risk_level": "high"}).score == 80
    for bad in ({"indicator": "evil.com", "risk_level": "high"}, {"indicator": "1.1.1.1"}):
        with pytest.raises(DomainError):
            acl.translate(bad)
