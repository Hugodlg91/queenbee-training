# Rendu J2 — état des portes qualité (étiquette `j2-rendu`)

## `make check` : vert

| Porte | Résultat |
|---|---|
| `ruff check . && ruff format --check .` | vert |
| `mypy` (strict, `src` + `bonus`) | vert |
| `python -m pytest --cov=src/queenbee --cov-fail-under=90` | 194 tests verts en ~1,8 s, couverture 99,5 % |
| `bandit -q -r src bonus` | aucun problème |
| `pip-audit` | aucune vulnérabilité connue |
| `PYTHONPATH=src lint-imports` | 1 kept, 0 broken |

Les spécifications du J2 (`tests/test_services.py`, `tests/test_adapters.py`), rouges au J1, sont vertes.
La suite tourne sans base ni réseau réels : la base par défaut est `:memory:`, la production fixe
`QUEENBEE_DB` dans `.env`.

## A1 · Cinq patterns défensifs

| Pattern | Code | DICP | Tests d'abus (`tests/test_defensive_patterns.py`) |
|---|---|---|---|
| Proxy | `application/access.py::IncidentReadProxy` | C | `test_abuse_proxy_refuses_principal_without_role`, `test_abuse_reader_cannot_modify_what_it_reads` |
| Décorateur | `adapters/outbound/notifiers.py::AuditedNotifier`, `RateLimitedNotifier` | D · P | `test_abuse_alert_flood_is_absorbed_and_counted`, `test_abuse_rate_limiter_cannot_be_disabled` |
| Adaptateur | `adapters/inbound/log_parser.py::parse_sshd_line` | I | `test_abuse_trapped_log_line_rejected` |
| Observateur (bonus) | `adapters/outbound/notifiers.py::AlertBus` | D | `test_abuse_broken_subscriber_does_not_block_others` |
| Commande + État | `adapters/outbound/response.py::BlockIpCommand`, `domain/model.py::Incident` | I · P | `test_abuse_trapped_ip_never_reaches_firewall`, `test_abuse_forbidden_transition_refused` |

Règles respectées : même interface que l'objet protégé, horloge injectée (aucun `time.sleep`),
tout rejet est compté (`denied`, `dropped`, `failures`, `rejected`).
Diagramme de classes : `docs/uml/classes_patterns_defensifs.puml`.

## A3 · Réécriture hexagonale testée

| Étape | Code |
|---|---|
| Ports | `application/ports.py` : `IncidentReader`, `IncidentRepository`, `Notifier`, `Firewall` (Protocol) |
| Cas d'usage | `application/services.py::IncidentService.move` : autoriser → vérifier → règle métier → persister |
| Adaptateurs d'entrée | `agent_api.py` (≤ 4 Kio, HMAC-SHA256 temps constant, schéma JSON strict), `log_parser.py`, `threat_feed.py` (couche anti-corruption) |
| Adaptateurs de sortie | dépôt mémoire (tests) et SQLite paramétré (prod) ; notifications auditées et limitées dans `bootstrap.py` |
| Contrat d'architecture | `lint-imports` : 1 kept, 0 broken |
| Tests malveillants | `tests/test_hexagon_abuse.py` : signature forgée ou rejouée, message altéré, champ en trop ou dupliqué, agent compromis, lecteur non autorisé, 2 tests Hypothesis |

## Remarque

`pip-audit` signalait des vulnérabilités dans **pip 25.1.1** (l'outil d'installation du `.venv`, pas une
dépendance du projet). Correction locale : `python -m pip install --upgrade pip` dans le `.venv`.
