# ruff: noqa
"""VARIANTE VOLONTAIREMENT FRAGILE de Queen Bee — usage LABORATOIRE uniquement (J3-A1).

Sept failles d'architecture à exploiter (en local), corriger, puis vérifier avec bandit/pip-audit.
Chaque faille porte un numéro FAILLE-n ; la correction de référence est dans src/queenbee.
"""
import json
import os
import re
import sqlite3
from collections.abc import Mapping
from datetime import datetime

from queenbee.domain.model import DomainError, SecurityEvent

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


def close_incident(user: str, incident_id: int) -> None:
    # FAILLE-5 : aucune vérification d'autorisation dans la couche service
    conn.execute("UPDATE incident SET status='closed' WHERE id=?", (incident_id,))


def call_enrichment_service(ip: str) -> dict:
    # FAILLE-6 : appel inter-services sans authentification mutuelle (ni mTLS, ni jeton)
    return {"ip": ip, "reputation": "unknown"}


def check_token(token: str, expected: str) -> bool:
    return token == expected                          # FAILLE-7 : comparaison non constante (timing)
