# Rendu J3 — état des portes qualité (étiquette `j3-rendu`)

| Porte | Résultat |
|---|---|
| `make check` (ruff, mypy, pytest + couverture, bandit, pip-audit, lint-imports) | vert : 212 tests en ~0,6 s, couverture 99,5 % |
| `python -m pytest -m lab -q` | 21 tests verts : les 7 failles sont corrigées et couvertes par un test inversé |
| `bandit -r labs -ll` | aucune alerte Medium / High |
| `pre-commit run gitleaks --all-files` et `gitleaks git` (historique) | aucune fuite ; 2 faux positifs vérifiés, déclarés dans `.gitleaksignore` |

## A1 · Revue de sécurité (`labs/vulnerable_queenbee.py`)

| # | Faille | Preuve | Correction | Test inversé | ADR |
|---|---|---|---|---|---|
| 1 | secret en dur partagé | écrite | une clé par service, depuis l'environnement | `test_lab_review.py::test_faille1_*` | 0002 |
| 2 | ReDoS | fournie | taille bornée, motif linéaire | `test_lab_vulnerable.py::test_faille2_redos_fixed_time_is_bounded` | 0003 |
| 3 | pickle | fournie | JSON au schéma strict | `test_lab_vulnerable.py::test_faille3_pickle_payload_rejected_without_running` | 0004 |
| 4 | SQL par f-string | fournie | requête paramétrée | `test_lab_vulnerable.py::test_faille4_sql_injection_returns_nothing` | 0005 |
| 5 | aucune autorisation | écrite | rôle vérifié en premier dans le cas d'usage | `test_lab_review.py::test_faille5_*` | 0006 |
| 6 | services non authentifiés | écrite | appel signé avec la clé du service (+ mTLS) | `test_lab_review.py::test_faille6_*` | 0007 |
| 7 | comparaison non constante | écrite (jeton espion, déterministe) | `hmac.compare_digest` | `test_lab_review.py::test_faille7_*` | 0008 |

Chaque faille a suivi le cycle : commit `test(lab): preuve` → `fix(lab)` → `test(lab): inversée` → `docs: ADR`.
Aucune « rustine » : pas de `try/except` qui avale l'erreur, chaque refus lève une erreur explicite.
Modèle de menaces : §6 (couche, STRIDE, DICP, ADR, test) et exigence EX-11.

Remarque : `legacy/log_watcher.py` (script hérité du J1, conservé pour les tests de caractérisation) garde
son alerte bandit `B608` ; il n'est ni importé par `src/` ni déployé.
