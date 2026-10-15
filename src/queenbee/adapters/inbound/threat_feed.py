"""Couche anti-corruption : le vocabulaire d'un flux externe ne pénètre pas le domaine."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from queenbee.domain.model import DomainError, ThreatIndicator

_SCORES: Final = {"low": 20, "medium": 50, "high": 80, "critical": 100}


class ThreatFeedTranslator:
    """Traduit {"indicator", "risk_level"} (format du fournisseur) en ThreatIndicator (le nôtre)."""

    def translate(self, raw: Mapping[str, object]) -> ThreatIndicator:
        if not isinstance(raw, Mapping):
            raise DomainError("entrée du flux invalide")
        indicator, level = raw.get("indicator"), raw.get("risk_level")
        if not isinstance(level, str) or level.lower() not in _SCORES:
            raise DomainError("niveau de risque inconnu")
        if not isinstance(indicator, str):
            raise DomainError("indicateur invalide")
        return ThreatIndicator(ip=indicator, score=_SCORES[level.lower()])
