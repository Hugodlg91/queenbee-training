# Recette : décision Go / No-Go (16/10/2026)

**Version recettée** : branche `main` du dépôt, étiquette `j3-rendu`.
**Décision : GO** pour une mise en service **pilote**, avec les réserves listées plus bas.

## Critères de sortie

| # | Critère | Seuil exigé | Résultat mesuré | Verdict |
|---|---|---|---|---|
| 1 | Style et bugs probables (`ruff check`, `ruff format --check`) | 0 erreur | 0 erreur | ✅ |
| 2 | Typage strict (`mypy`) | 0 erreur | 0 erreur (28 fichiers) | ✅ |
| 3 | Tests unitaires, d'abus, par propriétés (`pytest`) | 100 % verts | 212 verts, 0 échec, en ~0,6 s | ✅ |
| 4 | Couverture de `src/queenbee` | ≥ 90 % | 99,5 % | ✅ |
| 5 | Preuves de laboratoire (`pytest -m lab`) | 7 failles corrigées, tests inversés verts | 21 tests verts (7 failles) | ✅ |
| 6 | Analyse statique sécurité (`bandit` sur `src`, `bonus`, `labs`) | 0 alerte Medium / High | 0 | ✅ |
| 7 | Dépendances vulnérables (`pip-audit`) | 0 vulnérabilité connue | 0 | ✅ |
| 8 | Contrat d'architecture (`lint-imports`) | 1 kept, 0 broken | 1 kept, 0 broken | ✅ |
| 9 | Secrets dans le dépôt et l'historique (`gitleaks`) | 0 fuite | 0 (2 faux positifs vérifiés, déclarés dans `.gitleaksignore`) | ✅ |
| 10 | Exigences de sécurité tracées | 100 % des EX-nn ont un test vert | 11 / 11 (`docs/tracabilite_exigences_tests.md`) | ✅ |
| 11 | Suite rapide, sans base ni réseau réels | < 2 s | ~0,6 s, base `:memory:` | ✅ |

## Scénarios de recette fonctionnelle

| Scénario | Attendu | Test | Verdict |
|---|---|---|---|
| 5 échecs SSH depuis la même IP | 1 incident OPEN, 1 alerte au SOC | `test_services.py::test_detection_creates_incident_and_notifies` | ✅ |
| Lignes de journal mêlées de lignes piégées | incident créé, lignes piégées comptées | `test_adapters.py::test_end_to_end_facade` | ✅ |
| Un analyste trie puis ferme | OPEN → TRIAGED → CLOSED | `test_services.py::test_analyst_moves_incident` | ✅ |
| Un lecteur tente de fermer | refus, incident inchangé | `test_services.py::test_abuse_viewer_cannot_close_incident` | ✅ |
| Blocage d'une IP puis annulation | IP bloquée puis débloquée, cible piégée refusée | `test_services.py::test_command_undo` | ✅ |
| Tempête de 1 000 alertes | 3 transmises, 997 comptées | `test_services.py::test_abuse_rate_limiter_absorbs_alert_flood` | ✅ |

## Réserves (ce qui conditionne le passage du pilote à la production)

1. **Pas d'interface analyste** (écran ou API HTTP avec MFA) : les cas d'usage existent et sont testés,
   l'interface reste à construire.
2. **mTLS entre services** décrit dans l'infrastructure (`docs/infrastructure.md`), pas encore déployé.
3. **Ancienne clé `qb-admin-2026`** encore lisible dans l'historique Git : à **révoquer** partout où elle a servi.
4. **SQLite** convient au pilote (un seul processus) ; au-delà, prévoir une base serveur et la sauvegarde
   décrite dans `docs/exploitation_securite.md`.

Ces réserves sont reprises dans la trace de release (`docs/trace_de_release.md`).

## Rejouer la recette

```bash
source .venv/bin/activate
make check
python -m pytest -m lab -q
pre-commit run gitleaks --all-files
```
