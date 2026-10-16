"""Jour 3 — démonstrations d'exploitation SUR LA VARIANTE DE LABORATOIRE (labs/).

Chaque test PROUVE la faille. Après correction, l'étudiant inverse l'assertion.
"""

import pickle
import time

import pytest

from labs import vulnerable_queenbee as vuln

pytestmark = pytest.mark.lab


def test_faille3_pickle_executes_code_on_load(capsys: pytest.CaptureFixture[str]) -> None:
    class Payload:  # charge utile INOFFENSIVE : un simple print
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (print, ("PWNED: code exécuté pendant la désérialisation",))

    vuln.receive_agent_message(pickle.dumps(Payload()))
    assert "PWNED" in capsys.readouterr().out  # la simple lecture a exécuté du code


def test_faille2_redos_fixed_time_is_bounded() -> None:
    # Inversé : avant, +4 caractères multipliaient le temps par 16 (cost(22) > 4 * cost(18)).
    start = time.perf_counter()
    for n in range(1, 1_000):
        assert not vuln.is_valid_username("a" * n + "!")
    assert time.perf_counter() - start < 0.1  # 1 000 entrées piégées : quelques millisecondes
    assert vuln.is_valid_username("jean dupont")
    assert not vuln.is_valid_username("a" * 65)  # trop long : refusé avant la regex


def test_faille4_sql_injection_dumps_table() -> None:
    vuln.conn.execute("INSERT INTO incident (ip, status) VALUES ('10.0.0.1', 'open')")
    assert vuln.find_incidents("x' OR '1'='1")  # renvoie TOUTES les lignes
