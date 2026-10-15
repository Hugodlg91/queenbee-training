"""Adaptateur : ligne sshd (texte non fiable) -> SecurityEvent validé.

Taille bornée AVANT la regex ; regex ancrée (fullmatch), champs bornés, aucun quantificateur
imbriqué ; le domaine revalide derrière (IP, nom, fuseau).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Final

from queenbee.domain.model import DomainError, SecurityEvent

MAX_LINE_LENGTH: Final = 512

_SSHD: Final = re.compile(
    r"(?P<ts>[0-9T:.+\-Z]{19,35}) sshd(?:\[[0-9]{1,10}\])?: "
    r"(?P<verb>Failed|Accepted) (?:password|publickey) for (?:invalid user )?"
    r"(?P<user>[A-Za-z0-9._-]{1,64}) from (?P<ip>[0-9A-Fa-f:.]{2,45})"
    r"(?: port [0-9]{1,5}(?: ssh2)?)?",
    re.ASCII,
)
_ACTIONS: Final = {"Failed": "login_failed", "Accepted": "login_ok"}


def parse_sshd_line(line: str) -> SecurityEvent:
    if not isinstance(line, str) or len(line) > MAX_LINE_LENGTH:
        raise DomainError("ligne absente ou trop longue")
    match = _SSHD.fullmatch(line.rstrip("\r\n"))
    if match is None:
        raise DomainError("ligne sshd non reconnue")
    try:
        timestamp = datetime.fromisoformat(match["ts"])
    except ValueError as exc:
        raise DomainError("horodatage invalide") from exc
    return SecurityEvent(
        source_ip=match["ip"],
        username=match["user"],
        action=_ACTIONS[match["verb"]],
        timestamp=timestamp,
    )
