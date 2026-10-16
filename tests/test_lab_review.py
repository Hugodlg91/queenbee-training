"""Jour 3 · A1 — preuves des failles 1, 5, 6 et 7 sur la variante de LABORATOIRE (labs/).

Les preuves des failles 2, 3 et 4 sont fournies dans test_lab_vulnerable.py.
Cycle : preuve (le test montre la faille) -> correction -> test inversé (non-régression).
"""

from pathlib import Path

import pytest

from labs import vulnerable_queenbee as vuln
from queenbee.application.services import AccessDeniedError
from queenbee.domain.model import DomainError, Principal

pytestmark = pytest.mark.lab


KEY_A, KEY_B = "aa" * 32, "bb" * 32
ENV = {"QUEENBEE_ADMIN_KEY": KEY_A, "QUEENBEE_ENRICHMENT_KEY": KEY_B}


def test_faille1_no_hardcoded_secret_one_key_per_service() -> None:
    source = Path(vuln.__file__).read_text()
    assert "qb-admin-2026" not in source  # plus aucun secret dans le code
    assert not hasattr(vuln, "API_KEY")
    admin, enrichment = vuln.service_key("admin", ENV), vuln.service_key("enrichment", ENV)
    assert admin != enrichment  # une clé par service : en voler une n'ouvre pas les autres
    assert not vuln.check_token(admin, enrichment)


@pytest.mark.parametrize(
    ("service", "env"),
    [
        ("admin", {}),  # pas de clé : pas de valeur par défaut, le service refuse de démarrer
        ("admin", {"QUEENBEE_ADMIN_KEY": "qb-admin-2026"}),  # pas de l'hexadécimal
        ("admin", {"QUEENBEE_ADMIN_KEY": "aa" * 8}),  # trop courte
        ("database", {"QUEENBEE_DATABASE_KEY": KEY_A}),  # service inconnu
    ],
)
def test_faille1_missing_or_weak_key_refused(service: str, env: dict[str, str]) -> None:
    with pytest.raises(DomainError):
        vuln.service_key(service, env)


def _new_incident() -> int:
    cursor = vuln.conn.execute("INSERT INTO incident (ip, status) VALUES ('10.0.0.5', 'open')")
    assert cursor.lastrowid is not None
    return cursor.lastrowid


def _status(incident_id: int) -> str:
    row = vuln.conn.execute("SELECT status FROM incident WHERE id = ?", (incident_id,)).fetchone()
    return str(row[0])


@pytest.mark.parametrize(
    "intruder",
    ["mallory", Principal("mallory", frozenset()), Principal("bob", frozenset({"viewer"}))],
)
def test_faille5_only_an_analyst_can_close(intruder: object) -> None:
    incident_id = _new_incident()
    with pytest.raises(AccessDeniedError):
        vuln.close_incident(intruder, incident_id)  # type: ignore[arg-type]
    assert _status(incident_id) == "open"  # inversé : refus, et rien n'a bougé


def test_faille5_analyst_closes_once() -> None:
    incident_id = _new_incident()
    analyst = Principal("alice", frozenset({"analyst"}))
    vuln.close_incident(analyst, incident_id)
    assert _status(incident_id) == "closed"
    with pytest.raises(DomainError):
        vuln.close_incident(analyst, incident_id)  # déjà fermé
    with pytest.raises(DomainError):
        vuln.close_incident(analyst, 999_999)  # introuvable


def test_faille6_service_answers_anyone() -> None:
    # Aucun jeton, aucun certificat : n'importe quel processus du réseau obtient une réponse.
    assert vuln.call_enrichment_service("10.0.0.1")["reputation"] == "unknown"
    assert vuln.call_enrichment_service("'; DROP TABLE x;--")  # et sans même valider l'entrée
