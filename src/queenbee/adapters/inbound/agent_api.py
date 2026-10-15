"""Adaptateur : message d'un agent (TB1) -> SecurityEvent.

Dans cet ordre : taille bornée -> signature HMAC-SHA256 (temps constant) -> JSON strict -> domaine.
On ne lit jamais le contenu d'un message dont on n'a pas vérifié l'auteur.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime
from typing import Final

from queenbee.domain.model import DomainError, SecurityEvent

MAX_BODY_BYTES: Final = 4096
MIN_KEY_BYTES: Final = 32
FIELDS: Final = frozenset({"source_ip", "username", "action", "timestamp"})
_HEX_SIGNATURE: Final = re.compile(r"[0-9a-f]{64}")


class UnauthenticatedError(Exception):
    """Signature absente ou fausse : le message est rejeté sans être lu."""


def sign(body: bytes, key: bytes) -> str:
    if len(key) < MIN_KEY_BYTES:
        raise ValueError("clé HMAC trop courte")
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    data = dict(pairs)
    if len(data) != len(pairs):
        raise DomainError("clé JSON dupliquée")
    return data


def _reject_constant(name: str) -> object:
    raise DomainError(f"constante JSON interdite : {name}")


def parse_agent_message(body: bytes, signature: str, key: bytes) -> SecurityEvent:
    if not isinstance(body, bytes) or len(body) > MAX_BODY_BYTES:
        raise DomainError("message absent ou trop gros")
    if not isinstance(signature, str) or not _HEX_SIGNATURE.fullmatch(signature):
        raise UnauthenticatedError("signature absente ou mal formée")
    if not hmac.compare_digest(sign(body, key), signature):
        raise UnauthenticatedError("signature invalide")
    try:
        data = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DomainError("JSON invalide") from exc
    if not isinstance(data, dict) or set(data) != FIELDS:  # schéma strict : ni plus, ni moins
        raise DomainError("schéma du message invalide")
    if not all(isinstance(value, str) for value in data.values()):
        raise DomainError("champ non textuel")
    try:
        timestamp = datetime.fromisoformat(data["timestamp"])
    except ValueError as exc:
        raise DomainError("horodatage invalide") from exc
    return SecurityEvent(data["source_ip"], data["username"], data["action"], timestamp)
