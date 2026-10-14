"""Détections : Strategy (une règle par classe) et Composite (RuleSet)."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Protocol

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


# Motif repris tel quel du script d'origine (comportement conservé pendant l'extraction).
_LEGACY_SQLI: Final = re.compile(r"(union|select|insert|delete|drop|or|'|1=1)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class SqlInjectionRule:
    """Requêtes dont la cible ressemble à une injection SQL -> une alerte par IP."""

    def evaluate(self, requests: Sequence[HttpRequest]) -> list[Finding]:
        hits: dict[str, list[HttpRequest]] = {}
        for request in requests:
            if _LEGACY_SQLI.search(request.target):
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
