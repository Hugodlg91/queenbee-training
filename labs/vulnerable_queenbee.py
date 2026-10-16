# ruff: noqa
"""VARIANTE VOLONTAIREMENT FRAGILE de Queen Bee — usage LABORATOIRE uniquement (J3-A1).

Sept failles d'architecture à exploiter (en local), corriger, puis vérifier avec bandit/pip-audit.
Chaque faille porte un numéro FAILLE-n ; la correction de référence est dans src/queenbee.
"""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
from collections.abc import Mapping
from datetime import datetime

from queenbee.adapters.inbound.agent_api import UnauthenticatedError
from queenbee.application.services import AccessDeniedError
from queenbee.domain.model import DomainError, Principal, SecurityEvent

# FAILLE-1 corrigée : plus de secret dans le code. Une clé PAR SERVICE, injectée au démarrage
# par l'environnement (.env, coffre), sans valeur par défaut : sans clé, le service refuse de démarrer.
SERVICES = frozenset({"admin", "agent", "enrichment"})
MIN_KEY_BYTES = 32


def service_key(service: str, env: Mapping[str, str] | None = None) -> str:
    if service not in SERVICES:
        raise DomainError("service inconnu")
    env = os.environ if env is None else env
    key = env.get(f"QUEENBEE_{service.upper()}_KEY", "")
    try:
        valid = len(bytes.fromhex(key)) >= MIN_KEY_BYTES
    except ValueError:
        valid = False
    if not valid:
        raise DomainError(f"clé du service {service} absente ou trop courte")
    return key

# FAILLE-2 corrigée : plus de répétition imbriquée ((x+)*). Les mots sont séparés par UNE espace
# obligatoire : une seule façon de découper l'entrée, donc un temps linéaire.
USER_RE = re.compile(r"[a-zA-Z0-9]+(?: [a-zA-Z0-9]+)*")
MAX_USERNAME_LENGTH = 64

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE incident (id INTEGER PRIMARY KEY, ip TEXT, status TEXT)")


MAX_MESSAGE_BYTES = 4096
MESSAGE_FIELDS = frozenset({"source_ip", "username", "action", "timestamp"})


def receive_agent_message(raw: bytes) -> SecurityEvent:
    # FAILLE-3 corrigée : on accepte des DONNÉES (JSON), jamais du code (pickle exécute à la lecture).
    if not isinstance(raw, bytes) or len(raw) > MAX_MESSAGE_BYTES:
        raise DomainError("message absent ou trop gros")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DomainError("message non JSON") from exc
    if not isinstance(data, dict) or set(data) != MESSAGE_FIELDS:
        raise DomainError("schéma du message invalide")
    if not all(isinstance(value, str) for value in data.values()):
        raise DomainError("champ non textuel")
    try:
        timestamp = datetime.fromisoformat(data["timestamp"])
    except ValueError as exc:
        raise DomainError("horodatage invalide") from exc
    return SecurityEvent(data["source_ip"], data["username"], data["action"], timestamp)


def is_valid_username(name: str) -> bool:
    if not isinstance(name, str) or len(name) > MAX_USERNAME_LENGTH:  # borner AVANT la regex
        return False
    return USER_RE.fullmatch(name) is not None


def find_incidents(ip: str) -> list[tuple[int, str, str]]:
    # FAILLE-4 corrigée : requête paramétrée, le code SQL et la donnée voyagent séparément.
    return conn.execute("SELECT id, ip, status FROM incident WHERE ip = ?", (ip,)).fetchall()


def close_incident(who: Principal, incident_id: int) -> None:
    # FAILLE-5 corrigée : le contrôle est DANS le cas d'usage (pas dans l'interface), et en premier.
    if not isinstance(who, Principal) or not who.has("analyst"):  # 1. autoriser
        raise AccessDeniedError(getattr(who, "user", "inconnu"))
    row = conn.execute("SELECT status FROM incident WHERE id = ?", (incident_id,)).fetchone()
    if row is None:  # 2. vérifier
        raise DomainError("incident introuvable")
    if row[0] == "closed":  # 3. règle métier
        raise DomainError("incident déjà fermé")
    conn.execute("UPDATE incident SET status = 'closed' WHERE id = ?", (incident_id,))  # 4. persister


def sign_request(ip: str, key: str) -> str:
    """Côté appelant : signe la requête avec la clé du service d'enrichissement."""
    return hmac.new(bytes.fromhex(key), ip.encode(), hashlib.sha256).hexdigest()


def call_enrichment_service(ip: str, signature: str, key: str) -> dict[str, str]:
    # FAILLE-6 corrigée : le service authentifie l'appelant AVANT de répondre (HMAC avec sa clé
    # de service). En production : mTLS entre services en plus (voir infrastructure).
    if not isinstance(ip, str) or not isinstance(signature, str):
        raise UnauthenticatedError("appel non authentifié")
    if not check_token(signature, sign_request(ip, key)):
        raise UnauthenticatedError("appel non authentifié")
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise DomainError("IP invalide") from exc
    return {"ip": ip, "reputation": "unknown"}


def check_token(token: str, expected: str) -> bool:
    # FAILLE-7 corrigée : comparaison en temps constant ; le temps de réponse ne dit plus
    # combien de caractères étaient justes.
    if not isinstance(token, str) or not isinstance(expected, str):
        return False
    return hmac.compare_digest(token.encode(), expected.encode())
