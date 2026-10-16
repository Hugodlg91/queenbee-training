# Trace de release — Queen Bee 0.3.0 (16/10/2026, étiquette `j3-rendu`)

## Contenu de la version

| Jour | Ce qui a été livré | Étiquette |
|---|---|---|
| J1 · 14/10 | modèle de menaces STRIDE ; refactoring SOLID du script hérité ; patterns de création (Factory, Builder, fabrique abstraite, Prototype), suppression du Singleton ; bonus : refactoring de `tp2_log_parser.py` | `j1-rendu` |
| J2 · 15/10 | 5 patterns défensifs (Proxy, Décorateurs, Adaptateur, Observateur, Commande) ; réécriture hexagonale testée (API agents signée, couche anti-corruption, cas d'usage) ; ADR 0001, comparaison d'architectures, parcours, tranche verticale, C4 niveaux 1 et 2 | `j2-rendu` |
| J3 · 16/10 | revue de sécurité : 7 failles prouvées, corrigées, tests inversés, ADR 0002–0008 ; infrastructure cible (zones, matrice des flux, secrets, journaux, sauvegarde), ADR 0009–0011 ; dossier final | `j3-rendu` |

## Écarts par rapport aux consignes

| Écart | Raison | Impact |
|---|---|---|
| `make check` était rouge au rendu J1 | les tests du J2 importaient du code du J2 ; règle « on ne modifie pas les tests » | aucun : expliqué dans `docs/rendu_j1.md`, vert depuis le J2 |
| Base par défaut `:memory:` au lieu de `queenbee.db` | consigne « suite de tests sans base réelle » ; le test de bout en bout fourni utilise la configuration par défaut | la production doit fixer `QUEENBEE_DB` (`.env.example`) |
| Tests du laboratoire fournis modifiés | consigne du J3 : « après correction, l'étudiant inverse l'assertion » | les preuves d'origine restent lisibles dans l'historique Git |
| `pip` mis à jour dans le `.venv` | `pip-audit` signalait des failles de pip 25.1.1 lui-même | aucun sur le code ; à refaire sur chaque poste |
| Étiquette `j2-rendu` posée en retard | oubli le soir du J2 | posée sur `661848f` (dernier commit du J2) |
| `bandit` signale encore `B608` dans `legacy/log_watcher.py` | script hérité conservé **volontairement** : référence des tests de caractérisation du J1 | hors périmètre déployé (exclu de `src/`, jamais exécuté en production) |

## Dette assumée

| Dette | Risque si on ne la traite pas | Priorité |
|---|---|---|
| Pas d'interface analyste (UI ou API HTTP + MFA) | les cas d'usage ne sont utilisables que par du code | haute, avant la production |
| mTLS entre services décrit, pas déployé | un poste interne compromis pourrait se faire passer pour un service (signature HMAC en attendant) | haute |
| Ancienne clé `qb-admin-2026` lisible dans l'historique Git | réutilisation si elle a servi ailleurs | haute : **révoquer** partout |
| SQLite (un seul processus, un seul fichier) | pas de haute disponibilité ; sauvegarde à chaud délicate | moyenne : base serveur au-delà du pilote |
| Requête de service rejouable (pas d'horodatage signé, ADR 0007) | rejouer une demande d'enrichissement (lecture seule) | basse |
| Ports `Protocol` vérifiés par `mypy` seulement | une implémentation incomplète passerait si `mypy` n'était pas lancé | basse : `mypy` est dans `make check` et la CI |
| Pas de test de charge réel | volume de production supposé (quelques milliers d'événements/min) | moyenne |

**Décision de recette** : GO pilote, sous réserves (`docs/recette_go_no_go.md`).
