# Dossier de conception sécurisée — Queen Bee

Groupe : Corentin, Hugo, Praveen, Ugo · BC3 Architecture logicielle · 14–16 octobre 2026.

## Les 8 pièces du dossier

| # | Pièce | Où |
|---|---|---|
| 1 | **Modèle de menaces** (actifs, acteurs, DFD, frontières TB1–TB6, STRIDE, exigences EX-01–EX-11, revue des 7 failles) | [`threat_model.md`](threat_model.md) |
| 2 | **Code hexagonal testé** | `src/queenbee/` · `tests/` · contrôles : `make check`, `pytest -m lab` |
| 3 | **Traçabilité exigence ↔ test** | [`tracabilite_exigences_tests.md`](tracabilite_exigences_tests.md) |
| 4 | **ADR** | [`adr/`](adr/) : 0001 architecture hexagonale · 0002–0008 les 7 failles · 0009–0011 infrastructure |
| 5 | **Infrastructure** (zones, matrice des flux, secrets, journaux, sauvegarde) | [`infrastructure.md`](infrastructure.md) · [`exploitation_securite.md`](exploitation_securite.md) |
| 6 | **Diagrammes** | [`uml/`](uml/) : C4 contexte (niveau 1), conteneurs (2), composants (3) ; classes ; séquence |
| 7 | **Recette (Go / No-Go)** | [`recette_go_no_go.md`](recette_go_no_go.md) |
| 8 | **Trace de release** (écarts, dette) | [`trace_de_release.md`](trace_de_release.md) |

## Documents de travail

| Document | Jour |
|---|---|
| [`refactoring_legacy.md`](refactoring_legacy.md) · [`bonus_tp2_refactoring.md`](bonus_tp2_refactoring.md) | J1 |
| [`parcours_utilisateur.md`](parcours_utilisateur.md) · [`tranche_verticale.md`](tranche_verticale.md) · [`comparaison_architectures.md`](comparaison_architectures.md) | J2 |
| [`rendu_j1.md`](rendu_j1.md) · [`rendu_j2.md`](rendu_j2.md) · [`rendu_j3.md`](rendu_j3.md) | notes de rendu |
