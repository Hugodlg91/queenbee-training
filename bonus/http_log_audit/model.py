"""Objets du domaine : une requête ou une alerte invalide ne peut pas exister."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Final


class AuditError(ValueError):
    """Donnée refusée : ligne illisible, champ hors limites, paramètre invalide."""


ALLOWED_METHODS: Final = frozenset({"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"})
MAX_TARGET_LENGTH: Final = 2048
MAX_EXAMPLE_LENGTH: Final = 200
_RULE_NAME: Final = re.compile(r"[a-z][a-z0-9_]{0,31}")


def _check_ip(value: object) -> None:
    if not isinstance(value, str):
        raise AuditError("IP invalide")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise AuditError("IP invalide") from exc


def _is_bounded_text(value: object, max_length: int) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= max_length
        and value.isprintable()  # ni \x1b, ni \r, ni \n : rien qui pilote un terminal
    )


@dataclass(frozen=True, slots=True)
class HttpRequest:
    """Une ligne d'access.log. Tous ses champs viennent potentiellement de l'attaquant."""

    client_ip: str
    method: str
    target: str
    status: int

    def __post_init__(self) -> None:
        _check_ip(self.client_ip)
        if self.method not in ALLOWED_METHODS:
            raise AuditError("méthode HTTP hors liste blanche")
        if not _is_bounded_text(self.target, MAX_TARGET_LENGTH):
            raise AuditError("cible de requête invalide")
        if isinstance(self.status, bool) or not isinstance(self.status, int):
            raise AuditError("statut HTTP entier attendu")
        if not 100 <= self.status <= 599:
            raise AuditError("statut HTTP hors de [100, 599]")


@dataclass(frozen=True, slots=True)
class Finding:
    """Une alerte agrégée : une règle, une IP, combien de requêtes, un exemple."""

    rule: str
    client_ip: str
    count: int
    example: str

    def __post_init__(self) -> None:
        if not isinstance(self.rule, str) or not _RULE_NAME.fullmatch(self.rule):
            raise AuditError("nom de règle invalide")
        _check_ip(self.client_ip)
        if isinstance(self.count, bool) or not isinstance(self.count, int) or self.count < 1:
            raise AuditError("compte invalide")
        if not _is_bounded_text(self.example, MAX_EXAMPLE_LENGTH):
            raise AuditError("exemple invalide")
