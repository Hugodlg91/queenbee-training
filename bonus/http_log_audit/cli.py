"""Racine de composition : arguments -> lecture -> règles -> sortie. Plus de chemin global."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import Final, TextIO

from bonus.http_log_audit.model import AuditError, Finding
from bonus.http_log_audit.parser import bounded_lines, parse_lines
from bonus.http_log_audit.ports import FindingSink
from bonus.http_log_audit.rules import AuthBruteForceRule, RuleSet, SqlInjectionRule

MAX_SHOWN: Final = 120
EXIT_CLEAN, EXIT_ALERT, EXIT_ERROR = 0, 1, 2


def _safe(text: str) -> str:
    """Neutralise ce qui pourrait piloter le terminal ou forger une ligne de journal."""
    shown = "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in text[:MAX_SHOWN])
    return shown + ("…" if len(text) > MAX_SHOWN else "")


class ConsoleSink:
    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def emit(self, finding: Finding) -> None:
        print(
            f"[ALERT {finding.rule}] {finding.client_ip} : {finding.count} requête(s)"
            f" — ex. {_safe(finding.example)}",
            file=self._stream,
        )


def main(argv: Sequence[str] | None = None, *, sink: FindingSink | None = None) -> int:
    parser = argparse.ArgumentParser(description="Détecte brute force et injections SQL.")
    parser.add_argument("logfile", help="chemin de l'access.log à analyser")
    parser.add_argument("--threshold", type=int, default=3, help="nombre de 401 par IP")
    args = parser.parse_args(argv)
    sink = sink or ConsoleSink(sys.stdout)
    try:
        rules = RuleSet((AuthBruteForceRule(args.threshold), SqlInjectionRule()))
        with open(args.logfile, encoding="utf-8", errors="replace") as stream:
            report = parse_lines(bounded_lines(stream))
    except (AuditError, OSError) as exc:
        print(f"erreur : {_safe(str(exc))}", file=sys.stderr)
        return EXIT_ERROR
    findings = rules.evaluate(report.requests)
    for finding in findings:
        sink.emit(finding)
    print(f"{len(report.requests)} requête(s) analysée(s), {report.rejected} ligne(s) rejetée(s)")
    return EXIT_ALERT if findings else EXIT_CLEAN
