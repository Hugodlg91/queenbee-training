# Rendu J1 — état des portes qualité (étiquette `j1-rendu`)

## Vert

| Porte | Commande | Résultat |
|---|---|---|
| Style | `ruff check . && ruff format --check .` | vert |
| Typage | `mypy` (strict) | vert, 14 fichiers |
| Tests J1 | `python -m pytest tests/test_domain.py tests/test_creational.py tests/test_creational_abuse.py tests/test_legacy_characterization.py --cov=src/queenbee --cov-fail-under=90` | 61 tests verts, couverture 99,7 % |
| Sécurité du code | `bandit -q -r src -c pyproject.toml` | aucun problème |
| Dépendances | `pip-audit` | aucune vulnérabilité |
| Architecture | `PYTHONPATH=src lint-imports` | contrat hexagonal respecté |

## Ce qui reste rouge, et pourquoi

`make check` (cible `test`) s'arrête à la **collecte** de `tests/test_services.py` et
`tests/test_adapters.py`. Ce sont les spécifications du **J2**. Elles importent des modules qui
n'existent pas encore (`AuditedNotifier`, `RateLimitedNotifier`, `adapters/outbound/response.py`,
`application/access.py`, `IncidentService`, `Principal`, `adapters/inbound/*`, `QueenBee.ingest_lines`).
Pour la même raison, `python -m pytest -k secret` s'arrête aussi à la collecte. Le test J1 équivalent,
`tests/test_creational_abuse.py::test_secret_never_in_repr_or_str`, est vert. Lancez-le avec
`python -m pytest tests/test_creational_abuse.py -k secret`.

Les tests ne sont pas modifiés (règle : on change le code, jamais le test). Ces deux fichiers passeront
au vert avec les ateliers du J2.

## Autres remarques

- `pyproject.toml` : ajout de `[tool.ruff.lint.isort] known-first-party = ["queenbee", "tests"]`.
  Sans ce réglage, ruff classe `queenbee.adapters.inbound…` comme un paquet tiers tant que le module
  n'existe pas, et signale à tort l'ordre des imports (I001) dans les tests J2 fournis.
- `legacy/log_watcher.py` contient `SMTP_PASSWORD = "Sup3rS3cret!"` depuis le commit de départ :
  c'est le faux secret pédagogique du script hérité, fourni tel quel. `src/` ne contient aucun
  secret ; la vraie clé est dans `.env`, que Git ignore.
- Des `ResourceWarning` (connexion SQLite non fermée) s'affichent pendant les tests. Ils viennent des
  connexions `:memory:` créées par les tests, dont `ProdFactory(":memory:").repository()` dans
  `tests/test_creational.py`. Ce ne sont pas des échecs.
