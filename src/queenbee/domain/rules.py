"""Règles de détection : Strategy (une classe par règle), Composite (RuleSet), Factory."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Final, Protocol

from queenbee.domain.model import Alert, DomainError, SecurityEvent, Severity

MAX_THRESHOLD: Final = 10_000


class Rule(Protocol):
    """Contrat d'une règle : des événements validés en entrée, des alertes en sortie."""

    def evaluate(self, events: Iterable[SecurityEvent]) -> list[Alert]: ...


def _check_threshold(value: object) -> int:
    # bool est un int en Python : True passerait pour un seuil de 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise DomainError("seuil entier attendu")
    if not 1 <= value <= MAX_THRESHOLD:
        raise DomainError(f"seuil hors de [1, {MAX_THRESHOLD}]")
    return value


def _count_by_ip(events: Iterable[SecurityEvent], action: str) -> Counter[str]:
    return Counter(e.source_ip for e in events if e.action == action)


@dataclass(frozen=True, slots=True)
class BruteForceRule:
    """N échecs de connexion depuis la même IP -> alerte HIGH (logique de l'ancien LogWatcher)."""

    threshold: int = 5

    def __post_init__(self) -> None:  # rejoué par dataclasses.replace : le Prototype est revalidé
        _check_threshold(self.threshold)

    def evaluate(self, events: Iterable[SecurityEvent]) -> list[Alert]:
        return [
            Alert("brute_force", ip, Severity.HIGH, f"{n} échecs de connexion")
            for ip, n in _count_by_ip(events, "login_failed").items()
            if n >= self.threshold
        ]


@dataclass(frozen=True, slots=True)
class PortScanRule:
    """N sondes de port depuis la même IP -> alerte MEDIUM."""

    threshold: int = 20

    def __post_init__(self) -> None:
        _check_threshold(self.threshold)

    def evaluate(self, events: Iterable[SecurityEvent]) -> list[Alert]:
        return [
            Alert("port_scan", ip, Severity.MEDIUM, f"{n} sondes de port")
            for ip, n in _count_by_ip(events, "port_probe").items()
            if n >= self.threshold
        ]


@dataclass(frozen=True, slots=True)
class RuleSet:
    """Composite : se comporte comme une règle, délègue à toutes ses règles."""

    rules: tuple[Rule, ...]

    def __post_init__(self) -> None:
        if not self.rules:
            raise DomainError("RuleSet vide")

    def evaluate(self, events: Iterable[SecurityEvent]) -> list[Alert]:
        batch = list(events)  # un itérateur ne se parcourt qu'une fois
        return [alert for rule in self.rules for alert in rule.evaluate(batch)]


# Factory : registre fermé. Jamais de getattr/importlib sur une chaîne venue de la configuration.
_REGISTRY: Final[Mapping[str, Callable[..., Rule]]] = {
    "brute_force": BruteForceRule,
    "port_scan": PortScanRule,
}
_ALLOWED_KEYS: Final = frozenset({"kind", "threshold"})


def build_rule(spec: Mapping[str, object]) -> Rule:
    """Crée une règle depuis un dictionnaire (fichier de config, API admin...)."""
    if not isinstance(spec, Mapping) or not set(spec) <= _ALLOWED_KEYS:
        raise DomainError("spécification de règle invalide")
    kind = spec.get("kind")
    if not isinstance(kind, str) or kind not in _REGISTRY:
        raise DomainError("type de règle inconnu")
    if "threshold" not in spec:
        return _REGISTRY[kind]()
    return _REGISTRY[kind](_check_threshold(spec["threshold"]))
