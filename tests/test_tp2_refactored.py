"""Bonus J1-A2 — le nouveau code garde ce qui marchait et corrige chaque défaut figé.

Chaque `test_fixed_*` est l'inverse d'un `test_legacy_bug_*` de test_tp2_characterization.py.
"""

import contextlib
import time
from dataclasses import FrozenInstanceError
from io import StringIO
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from bonus.http_log_audit.cli import main
from bonus.http_log_audit.model import AuditError, Finding, HttpRequest
from bonus.http_log_audit.parser import (
    MAX_LINE_LENGTH,
    bounded_lines,
    parse_access_line,
    parse_lines,
)
from bonus.http_log_audit.rules import AuthBruteForceRule, RuleSet, SqlInjectionRule
from tests.test_tp2_characterization import SAMPLE, run_legacy

PREFIX = "10.0.0.7 - - [16/Sep/2026:10:00:01] "
RULES = RuleSet((AuthBruteForceRule(), SqlInjectionRule()))


def line(target: str = "/", status: int = 200, size: str = "12", tail: str = "") -> str:
    return f'{PREFIX}"GET {target} HTTP/1.1" {status} {size}{tail}'


def findings(lines: list[str]) -> set[tuple[str, str, int]]:
    report = parse_lines(lines)
    return {(f.rule, f.client_ip, f.count) for f in RULES.evaluate(report.requests)}


# --- Ce qui marchait : même résultat que le script d'origine ---------------------------------


def test_same_findings_as_legacy_on_sample(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    old = run_legacy(SAMPLE, tmp_path, monkeypatch, capsys)
    old_bruteforce = {o.split("L'IP ")[1].split()[0] for o in old if "BRUTE-FORCE" in o}
    old_sqli = {o.split("depuis ")[1].split()[0] for o in old if "SQLi" in o}
    new = findings(SAMPLE.read_text().splitlines())
    assert {ip for rule, ip, _ in new if rule == "auth_bruteforce"} == old_bruteforce
    assert {ip for rule, ip, _ in new if rule == "sql_injection"} == old_sqli
    assert ("auth_bruteforce", "10.0.0.15", 4) in new


def test_under_threshold_is_quiet() -> None:
    assert findings([line("/login", 401)] * 2) == set()


# --- Les défauts figés sont corrigés ---------------------------------------------------------


@pytest.mark.parametrize(
    "target", ["/forum", "/order?id=3", "/error", "/search?q=rock+and+roll", "/selection"]
)
def test_fixed_innocent_words_are_not_sqli(target: str) -> None:
    assert findings([line(target)]) == set()


def test_fixed_response_size_401_is_not_a_failure() -> None:
    assert findings([line("/img", 200, "401", ' "-" "curl"')] * 3) == set()


@pytest.mark.parametrize(
    "target",
    [
        "/admin' OR '1'='1",
        "/item?id=1%27%20%4fR%20%271%27%3d%271",  # encodé une fois
        "/item?id=1%2527%2520OR%2520%25271%2527%253d%25271",  # encodé deux fois
        "/p?id=1+UNION/**/SELECT+password+FROM+users",
        "/p?id=1;DROP TABLE users",
        "/a?id=1 or 1=1",
        "/login?user=admin'--",
        "/p?id=1 AND SLEEP(5)",
    ],
)
def test_fixed_encoded_and_obfuscated_injections_are_detected(target: str) -> None:
    assert findings([line(target)]) == {("sql_injection", "10.0.0.7", 1)}


def test_fixed_terminal_escape_never_reaches_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = tmp_path / "access.log"
    log.write_text(
        line("/x", tail=' "-" "\x1b[2J\x1b[31m\' or 1=1"') + "\n" + line("/a' or '1'='1")
    )
    main([str(log)])
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "sql_injection" in out


def test_one_alert_per_ip_not_per_line() -> None:
    assert findings([line("/a?id=1 or 1=1")] * 10_000) == {("sql_injection", "10.0.0.7", 10_000)}


# --- Entrées piégées : rejetées, jamais de plantage ------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        line("/x").replace("10.0.0.7", "999.1.1.1"),
        line("/x").replace("GET", "HACK"),
        line("/x", 999),
        line("/x") + "A" * MAX_LINE_LENGTH,
        "",
        "\x00\x00\x00",
        "10.0.0.7 - - [x] GET / 200 1",
    ],
)
def test_malicious_lines_rejected(bad: str) -> None:
    with pytest.raises(AuditError):
        parse_access_line(bad)


@given(st.text(max_size=600))
def test_parser_never_crashes_unexpectedly(text: str) -> None:
    with contextlib.suppress(AuditError):
        parse_access_line(text)


def test_parser_is_fast_on_adversarial_input() -> None:
    evil = f'{PREFIX}"GET /{" " * 2000} HTTP/1.1 200 1'
    start = time.perf_counter()
    for _ in range(1_000):
        with pytest.raises(AuditError):
            parse_access_line(evil)
    assert time.perf_counter() - start < 1.0


def test_giant_line_is_cut_and_counted_without_loading_it() -> None:
    stream = StringIO("A" * 100_000 + "\n" + line("/ok") + "\n")
    chunks = list(bounded_lines(stream))
    assert len(chunks[0]) == MAX_LINE_LENGTH + 1
    report = parse_lines(chunks)
    assert (len(report.requests), report.rejected) == (1, 1)


# --- Objets du domaine et règles -------------------------------------------------------------


def test_request_is_immutable() -> None:
    request = parse_access_line(line("/x"))
    with pytest.raises(FrozenInstanceError):
        request.status = 401  # type: ignore[misc]


@pytest.mark.parametrize("status", [True, "200", 42])
def test_invalid_status_cannot_exist(status: object) -> None:
    with pytest.raises(AuditError):
        HttpRequest("10.0.0.7", "GET", "/", status)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "args",
    [
        ("Bad Rule", "10.0.0.7", 1, "x"),
        ("sql_injection", "localhost", 1, "x"),
        ("sql_injection", "10.0.0.7", 0, "x"),
        ("sql_injection", "10.0.0.7", True, "x"),
        ("sql_injection", "10.0.0.7", 1, "\x1b[2J"),
        ("sql_injection", "10.0.0.7", 1, "x" * 1_000),
    ],
)
def test_invalid_finding_cannot_exist(args: tuple[str, str, int, str]) -> None:
    with pytest.raises(AuditError):
        Finding(*args)


@pytest.mark.parametrize("threshold", [True, 0, -1, 10**9, "3"])
def test_abuse_threshold_rejected(threshold: object) -> None:
    with pytest.raises(AuditError):
        AuthBruteForceRule(threshold)  # type: ignore[arg-type]


def test_empty_ruleset_rejected() -> None:
    with pytest.raises(AuditError):
        RuleSet(())


# --- CLI : codes de sortie, erreurs propres --------------------------------------------------


def test_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    clean = tmp_path / "clean.log"
    clean.write_text(line("/index.html") + "\n")
    assert main([str(clean)]) == 0
    assert main([str(SAMPLE)]) == 1
    assert main([str(tmp_path / "absent.log")]) == 2
    assert main([str(SAMPLE), "--threshold", "0"]) == 2
    assert "1 requête(s) analysée(s), 0 ligne(s) rejetée(s)" in capsys.readouterr().out


def test_cli_survives_non_utf8_bytes(tmp_path: Path) -> None:
    log = tmp_path / "binary.log"
    log.write_bytes(b"\xff\xfe\x00garbage\n" + line("/a' or '1'='1").encode())
    assert main([str(log)]) == 1
```
