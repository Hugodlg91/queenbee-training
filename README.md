# Queen Bee — fil rouge du module BC3 · Architecture logicielle

**ITIS MAST CYBER 4 · ITIS MAST DEV 4** — tronc commun, 14, 15 et 16 octobre 2026

Mini-plateforme de détection : des **agents** (« abeilles ») remontent des événements de sécurité,
la **reine** les valide, détecte (règles), ouvre des **incidents** et alerte les analystes du SOC.

```
src/queenbee/
  domain/        # entités, objets-valeurs, règles métier — AUCUNE dépendance technique
  application/   # cas d'usage + ports (Protocol) + contrôle d'accès
  adapters/      # inbound (logs, API agents) / outbound (sqlite, notifiers, pare-feu)
  config.py      # Builder -> Settings figé ; secrets depuis l'environnement
  bootstrap.py   # composition root + Facade QueenBee
legacy/          # code de départ « Python Scripting Sécu » (MAUVAIS, à refactorer — J1)
labs/            # variante volontairement vulnérable (LABO uniquement — J3)
tests/           # pytest + hypothesis, tests d'abus inclus
```

## Démarrer (Python ≥ 3.12, recommandé 3.13/3.14)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make check          # = lint + types + tests + sécurité + architecture
```

## Portes qualité (toutes doivent être vertes avant un rendu)

| Commande | Rôle |
|---|---|
| `ruff check . && ruff format --check .` | style, bugs probables, règles sécurité `S` (bandit intégré) |
| `mypy` | typage strict |
| `pytest --cov=src/queenbee` | tests unitaires, d'abus, par propriétés |
| `bandit -r src -c pyproject.toml` | analyse statique sécurité |
| `pip-audit` | dépendances vulnérables (base PyPA / OSV) |
| `PYTHONPATH=src lint-imports` | contrat d'architecture : les couches ne s'inversent pas |

> `legacy/` et `labs/` contiennent du code **volontairement dangereux**. Ne jamais les déployer.

## Kit formateur / Projet training

- **Kit formateur** : ce dépôt complet (`src/` = correction de référence, 40 tests verts).
- **Projet training** (remis aux étudiants) : même dépôt sans `src/queenbee/`, avec des gabarits vides
  dans `docs/` ; les tests servent de spécifications exécutables
  (J1 : `tests/test_domain.py` + `tests/test_creational.py`, J2 : `tests/test_services.py` + `tests/test_adapters.py`,
  J3 : `tests/test_lab_vulnerable.py`).

## Noms anglais dans le code, noms français sur les slides

Les slides montrent le code avec des noms français (`EvenementSecurite`, `RegleForceBrute`…) pour faciliter
la lecture. Ce dépôt garde les noms **anglais** (`SecurityEvent`, `BruteForceRule`…), comme en entreprise :
ce sont eux que les tests importent. La **fiche de correspondance français ↔ anglais** donne l'équivalence.

## Démo du parcours (J2)

```bash
export QUEENBEE_AGENT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
PYTHONPATH=src python demo_parcours.py
```
