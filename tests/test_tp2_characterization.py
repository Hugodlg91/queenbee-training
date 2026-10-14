"""Bonus J1-A2 — filet de sécurité : ce que fait legacy/tp2_log_parser.py AVANT refactoring.

Les tests `test_legacy_*` figent ce qui marche (à conserver) ; les tests `test_legacy_bug_*`
figent des défauts observés (à faire disparaître dans le nouveau code).
"""

from pathlib import Path

import pytest

from legacy import tp2_log_parser as legacy

SAMPLE = Path(__file__).parent / "data" / "tp2_access.log"


def run_legacy(
    lines: list[str] | Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> list[str]:
    if isinstance(lines, Path):
        log = lines
    else:
        log = tmp_path / "access.log"
        log.write_text("\n".join(lines) + "\n")
    monkeypatch.setattr(legacy, "LOG_FILE", str(log))
    legacy.analyze_logs()
    return capsys.readouterr().out.splitlines()


def test_legacy_sample_raises_bruteforce_and_sqli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out = run_legacy(SAMPLE, tmp_path, monkeypatch, capsys)
    assert [line for line in out if "BRUTE-FORCE" in line] == [
        "[ALERT BRUTE-FORCE] L'IP 10.0.0.15 cumule 4 échecs d'authentification."
    ]
    assert [line.split(" -> ")[0] for line in out if "SQLi" in line] == [
        "[ALERT SQLi] Injection détectée depuis 192.168.1.100"
    ]


def test_legacy_two_failures_are_not_bruteforce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    line = '10.0.0.15 - - [16/Sep/2026:10:00:05] "POST /login HTTP/1.1" 401 512'
    assert run_legacy([line, line], tmp_path, monkeypatch, capsys) == []


def test_legacy_bug_innocent_word_flagged_as_sqli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # « or » sans bornes de mot : /forum, /order, /error... sont tous des « injections ».
    line = '192.168.1.50 - - [16/Sep/2026:10:00:01] "GET /forum HTTP/1.1" 200 1024'
    assert len(run_legacy([line], tmp_path, monkeypatch, capsys)) == 1


def test_legacy_bug_response_size_401_counted_as_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # « 401 » cherché n'importe où dans la ligne : une réponse 200 de 401 octets compte comme échec.
    line = '10.0.0.9 - - [16/Sep/2026:10:00:01] "GET /img HTTP/1.1" 200 401 "-" "curl"'
    out = run_legacy([line] * 3, tmp_path, monkeypatch, capsys)
    assert any("BRUTE-FORCE] L'IP 10.0.0.9" in line for line in out)


def test_legacy_bug_url_encoded_injection_missed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Ce qu'un vrai serveur journalise : la charge est encodée, le motif ne la voit plus.
    payload = "/item?id=1%27%20%4fR%20%271%27%3d%271"  # 1' OR '1'='1
    line = f'10.0.0.7 - - [16/Sep/2026:10:00:01] "GET {payload} HTTP/1.1" 200 12'
    assert run_legacy([line], tmp_path, monkeypatch, capsys) == []


def test_legacy_bug_terminal_escape_printed_raw(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # La ligne de l'attaquant est recopiée telle quelle dans le terminal de l'analyste (CWE-150).
    line = (
        '10.0.0.7 - - [16/Sep/2026:10:00:01] "GET /x HTTP/1.1" 200 1 "-" "\x1b[2J\x1b[31m\' or 1=1"'
    )
    out = run_legacy([line], tmp_path, monkeypatch, capsys)
    assert "\x1b[2J" in out[0]
