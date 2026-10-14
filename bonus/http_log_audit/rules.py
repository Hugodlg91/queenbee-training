"""Détections : Strategy (une règle par classe) et Composite (RuleSet)."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Protocol
from urllib.parse import unquote_plus

from bonus.http_log_audit.model import MAX_EXAMPLE_LENGTH, AuditError, Finding, HttpRequest

MAX_THRESHOLD: Final = 10_000


class Rule(Protocol):
    def evaluate(self, requests: Sequence[HttpRequest]) -> list[Finding]: ...


@dataclass(frozen=True, slots=True)
class AuthBruteForceRule:
    """N réponses 401 pour la même IP -> alerte (seuil 3 dans le script d'origine)."""

    threshold: int = 3

    def __post_init__(self) -> None:
        if isinstance(self.threshold, bool) or not isinstance(self.threshold, int):
            raise AuditError("seuil entier attendu")
        if not 1 <= self.threshold <= MAX_THRESHOLD:
            raise AuditError(f"seuil hors de [1, {MAX_THRESHOLD}]")

    def evaluate(self, requests: Sequence[HttpRequest]) -> list[Finding]:
        failures = Counter(r.client_ip for r in requests if r.status == 401)
        return [
            Finding("auth_bruteforce", ip, n, f"{n} réponses 401")
            for ip, n in failures.items()
            if n >= self.threshold
        ]


# Bornes de mot et quantificateurs bornés : « /forum » n'est plus une injection, pas de ReDoS.
_SQLI: Final = re.compile(
    r"'\s{0,5}(?:or|and)\s{1,5}'?\w{1,20}'?\s{0,5}=?"  # ' or '1'='1
    r"|\b(?:or|and)\s{1,5}\d{1,10}\s{0,5}=\s{0,5}\d{1,10}"  # or 1=1
    r"|\bunion\s{1,10}(?:all\s{1,10})?select\b"
    r"|;\s{0,5}(?:drop|delete|insert|update|shutdown)\b"
    r"|'\s{0,5}(?:--|#)"
    r"|\b(?:sleep|benchmark|pg_sleep)\s{0,5}\(",
)
_SQL_COMMENT: Final = re.compile(r"/\*[^*]{0,200}\*/")
_URL_DECODE_PASSES: Final = 2


def normalize_target(target: str) -> str:
    """Ce que verra vraiment l'application : décodage URL (borné), commentaires SQL repliés."""
    decoded = target
    for _ in range(_URL_DECODE_PASSES):  # %2527 -> %27 -> '
        once = unquote_plus(decoded)
        if once == decoded:
            break
        decoded = once
    return " ".join(_SQL_COMMENT.sub(" ", decoded).lower().split())


@dataclass(frozen=True, slots=True)
class SqlInjectionRule:
    """Requêtes dont la cible ressemble à une injection SQL -> une alerte par IP."""

    def evaluate(self, requests: Sequence[HttpRequest]) -> list[Finding]:
        hits: dict[str, list[HttpRequest]] = {}
        for request in requests:
            if _SQLI.search(normalize_target(request.target)):
                hits.setdefault(request.client_ip, []).append(request)
        return [
            Finding("sql_injection", ip, len(rs), rs[0].target[:MAX_EXAMPLE_LENGTH])
            for ip, rs in hits.items()
        ]


@dataclass(frozen=True, slots=True)
class RuleSet:
    """Composite : se comporte comme une règle, délègue à toutes les siennes."""

    rules: tuple[Rule, ...]

    def __post_init__(self) -> None:
        if not self.rules:
            raise AuditError("RuleSet vide")

    def evaluate(self, requests: Sequence[HttpRequest]) -> list[Finding]:
        return [finding for rule in self.rules for finding in rule.evaluate(requests)]
