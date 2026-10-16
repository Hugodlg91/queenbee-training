"""Jour 3 · A1 — preuves des failles 1, 5, 6 et 7 sur la variante de LABORATOIRE (labs/).

Les preuves des failles 2, 3 et 4 sont fournies dans test_lab_vulnerable.py.
Cycle : preuve (le test montre la faille) -> correction -> test inversé (non-régression).
"""

from pathlib import Path

import pytest

from labs import vulnerable_queenbee as vuln

pytestmark = pytest.mark.lab


def test_faille1_secret_hardcoded_and_shared() -> None:
    source = Path(vuln.__file__).read_text()
    assert '"qb-admin-2026"' in source  # quiconque lit le dépôt a la clé
    assert vuln.check_token("qb-admin-2026")  # et elle ouvre la porte
