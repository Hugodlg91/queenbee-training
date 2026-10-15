"""Proxy : contrôle d'accès devant la lecture des incidents (confidentialité)."""

from __future__ import annotations

from typing import Final
from uuid import UUID

from queenbee.application.ports import IncidentReader
from queenbee.application.services import AccessDeniedError
from queenbee.domain.model import Incident, Principal

READ_ROLES: Final = frozenset({"viewer", "analyst"})


class IncidentReadProxy:
    """Même interface que le dépôt (IncidentReader) : le client ne voit pas la différence.

    Le rôle est vérifié à CHAQUE appel, et le lecteur reçoit des copies : modifier ce qu'il lit
    ne change pas ce qui est stocké.
    """

    def __init__(self, inner: IncidentReader, principal: Principal) -> None:
        self._inner = inner
        self._principal = principal
        self.denied = 0

    def _authorize(self) -> None:
        if not self._principal.roles & READ_ROLES:
            self.denied += 1
            raise AccessDeniedError(self._principal.user)

    def get(self, incident_id: UUID) -> Incident | None:
        self._authorize()
        incident = self._inner.get(incident_id)
        return None if incident is None else _copy(incident)

    def list_open(self) -> list[Incident]:
        self._authorize()
        return [_copy(i) for i in self._inner.list_open()]


def _copy(incident: Incident) -> Incident:
    return Incident(incident.alert, id=incident.id, status=incident.status)
