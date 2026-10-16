# ruff: noqa
"""VARIANTE VOLONTAIREMENT FRAGILE de Queen Bee — usage LABORATOIRE uniquement (J3-A1).

Sept failles d'architecture à exploiter (en local), corriger, puis vérifier avec bandit/pip-audit.
Chaque faille porte un numéro FAILLE-n ; la correction de référence est dans src/queenbee.
"""
import os
import pickle
import re
import sqlite3
from collections.abc import Mapping

from queenbee.domain.model import DomainError

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


def receive_agent_message(raw: bytes):
    return pickle.loads(raw)                          # FAILLE-3 : désérialisation non sûre (RCE)


def is_valid_username(name: str) -> bool:
    if not isinstance(name, str) or len(name) > MAX_USERNAME_LENGTH:  # borner AVANT la regex
        return False
    return USER_RE.fullmatch(name) is not None


def find_incidents(ip: str):
    # FAILLE-4 : injection SQL (f-string)
    return conn.execute(f"SELECT * FROM incident WHERE ip = '{ip}'").fetchall()


def close_incident(user: str, incident_id: int) -> None:
    # FAILLE-5 : aucune vérification d'autorisation dans la couche service
    conn.execute("UPDATE incident SET status='closed' WHERE id=?", (incident_id,))


def call_enrichment_service(ip: str) -> dict:
    # FAILLE-6 : appel inter-services sans authentification mutuelle (ni mTLS, ni jeton)
    return {"ip": ip, "reputation": "unknown"}


def check_token(token: str, expected: str) -> bool:
    return token == expected                          # FAILLE-7 : comparaison non constante (timing)
