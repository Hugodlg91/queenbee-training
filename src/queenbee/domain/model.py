"""Entités et objets-valeurs du domaine : un objet invalide ne peut pas exister."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, IntEnum
from typing import Final
from uuid import UUID, uuid4


class DomainError(ValueError):
    """Une donnée viole une règle du domaine (entrée refusée, transition interdite...)."""


# Ancrée par fullmatch, bornée : ni `.*` gourmand, ni backtracking exponentiel.
_USERNAME: Final = re.compile(r"[A-Za-z0-9._-]{1,64}")
_RULE_NAME: Final = re.compile(r"[a-z][a-z0-9_]{0,31}")
MAX_DETAIL_LENGTH: Final = 200

ALLOWED_ACTIONS: Final = frozenset({"login_failed", "login_ok", "port_probe"})


def _check_ip(value: object) -> None:
    if not isinstance(value, str):
        raise DomainError("IP invalide")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise DomainError("IP invalide") from exc


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Un fait remonté par un agent. Toutes ses données viennent potentiellement de l'attaquant."""

    source_ip: str
    username: str
    action: str
    timestamp: datetime

    def __post_init__(self) -> None:
        _check_ip(self.source_ip)
        if not isinstance(self.username, str) or not _USERNAME.fullmatch(self.username):
            raise DomainError("nom d'utilisateur invalide")
        if self.action not in ALLOWED_ACTIONS:
            raise DomainError("action hors liste blanche")
        if not isinstance(self.timestamp, datetime) or self.timestamp.tzinfo is None:
            raise DomainError("horodatage sans fuseau")


@dataclass(frozen=True, slots=True)
class Alert:
    """Résultat d'une règle : quelle règle, sur quelle IP, avec quelle gravité."""

    rule: str
    source_ip: str
    severity: Severity
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.rule, str) or not _RULE_NAME.fullmatch(self.rule):
            raise DomainError("nom de règle invalide")
        _check_ip(self.source_ip)
        if isinstance(self.severity, bool):
            raise DomainError("gravité invalide")
        try:
            object.__setattr__(self, "severity", Severity(self.severity))  # 3 -> Severity.HIGH
        except ValueError as exc:
            raise DomainError("gravité invalide") from exc
        if not isinstance(self.detail, str) or len(self.detail) > MAX_DETAIL_LENGTH:
            raise DomainError("détail invalide")


class IncidentStatus(Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    CONTAINED = "contained"
    CLOSED = "closed"


# State : seules ces transitions existent ; on ne ferme pas un incident sans l'avoir trié.
_TRANSITIONS: Final[dict[IncidentStatus, frozenset[IncidentStatus]]] = {
    IncidentStatus.OPEN: frozenset({IncidentStatus.TRIAGED}),
    IncidentStatus.TRIAGED: frozenset({IncidentStatus.CONTAINED, IncidentStatus.CLOSED}),
    IncidentStatus.CONTAINED: frozenset({IncidentStatus.CLOSED}),
    IncidentStatus.CLOSED: frozenset(),
}


class Incident:
    """Entité : identité stable, statut qui ne change que par `transition_to`."""

    __slots__ = ("_status", "alert", "id")

    def __init__(
        self,
        alert: Alert,
        *,
        id: UUID | None = None,
        status: IncidentStatus = IncidentStatus.OPEN,
    ) -> None:
        if not isinstance(alert, Alert) or not isinstance(status, IncidentStatus):
            raise DomainError("incident invalide")
        self.alert = alert
        self.id = id or uuid4()
        self._status = status

    @property
    def status(self) -> IncidentStatus:
        return self._status

    def transition_to(self, target: IncidentStatus) -> None:
        if target not in _TRANSITIONS[self._status]:
            raise DomainError(f"transition interdite : {self._status.value} -> {target.value}")
        self._status = target

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Incident):
            return NotImplemented
        return (self.id, self.alert, self._status) == (other.id, other.alert, other._status)

    def __hash__(self) -> int:
        return hash(self.id)

    def __repr__(self) -> str:
        return f"Incident(id={self.id}, rule={self.alert.rule!r}, status={self._status.value})"
