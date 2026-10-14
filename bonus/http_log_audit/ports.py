"""Port de sortie : où vont les alertes (console, fichier, SIEM), à l'insu des règles."""

from __future__ import annotations

from typing import Protocol

from bonus.http_log_audit.model import Finding


class FindingSink(Protocol):
    def emit(self, finding: Finding) -> None: ...
