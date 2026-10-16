# Traçabilité : exigence ↔ menace ↔ code ↔ test

Chaque exigence du modèle de menaces (`docs/threat_model.md`, §5 et §6) est reliée à la menace qu'elle
traite, au code qui l'applique et au test qui échoue si elle est violée. Tous les tests cités sont verts
(`make check` et `pytest -m lab`, version du 16/10).

| Exigence | En une phrase | STRIDE · frontière | DICP | Code qui l'applique | Test(s) qui la prouvent |
|---|---|---|---|---|---|
| **EX-01** | tout message d'agent est signé HMAC-SHA256, vérifié en temps constant | S · TB1 | I | `adapters/inbound/agent_api.py` | `test_adapters.py::test_abuse_forged_signature_rejected` |
| **EX-02** | une ligne piégée est rejetée, 1 000 lignes en moins de 1 s | D · TB1 | D | `adapters/inbound/log_parser.py` | `test_adapters.py::test_parser_is_fast_on_adversarial_input` |
| **EX-03** | un `SecurityEvent` invalide ne peut pas exister, et il est figé | T · TB1 | I | `domain/model.py::SecurityEvent` | `test_domain.py::test_invalid_event_cannot_exist`, `::test_event_is_immutable` |
| **EX-04** | toute requête SQL est paramétrée | T · TB2 | C, I | `adapters/outbound/repositories.py` | `test_services.py::test_sqlite_repo_resists_injection`, `test_creational_abuse.py::test_sqlite_stores_hostile_text_verbatim` |
| **EX-05** | la clé vient de l'environnement, ≥ 32 octets, jamais affichée | I · TB5 | C | `config.py::Settings` (`repr=False`) | `test_adapters.py::test_secret_never_printed`, `::test_missing_secret_refuses_to_start`, `test_creational_abuse.py::test_secret_never_in_repr_or_str` |
| **EX-06** | seul un analyste change un statut ; pas de clôture sans triage | E · TB4 | I | `application/services.py::IncidentService`, `domain/model.py::Incident` | `test_services.py::test_abuse_viewer_cannot_close_incident`, `test_domain.py::test_state_forbids_skipping_triage` |
| **EX-07** | toute alerte est journalisée ; au plus N alertes par fenêtre | R, D · TB3 | P, D | `adapters/outbound/notifiers.py` (Décorateurs) | `test_services.py::test_audit_decorator_logs`, `::test_abuse_rate_limiter_absorbs_alert_flood` |
| **EX-08** | règles créées seulement depuis le registre ; IP de blocage validée | E · TB5, TB3 | I | `domain/rules.py::build_rule`, `adapters/outbound/response.py` | `test_domain.py::test_factory_rejects_unknown_rule`, `::test_factory_rejects_bool_threshold`, `test_services.py::test_command_undo` |
| **EX-09** | tout indicateur externe passe par la couche anti-corruption | T · TB6 | I | `adapters/inbound/threat_feed.py` | `test_adapters.py::test_anti_corruption_layer_translates_and_rejects`, `test_hexagon_abuse.py::test_abuse_threat_feed_garbage_rejected` |
| **EX-10** | un message signé mais mal formé (agent compromis) est rejeté | T, E · TB1 | I | `adapters/inbound/agent_api.py` (schéma strict) | `test_adapters.py::test_abuse_extra_field_rejected`, `test_hexagon_abuse.py::test_abuse_signed_but_malformed_message_rejected` |
| **EX-11** | pas de pickle ; secrets comparés en temps constant ; services authentifiés | T, E, S · TB1, entre services | I, C | `labs/vulnerable_queenbee.py` (corrigé), `agent_api.py` | `test_lab_vulnerable.py::test_faille3_pickle_payload_rejected_without_running`, `test_lab_review.py::test_faille7_token_compared_in_constant_time`, `::test_faille6_unauthenticated_caller_refused` |

## Couverture

| STRIDE | Exigences | | DICP | Exigences |
|---|---|---|---|---|
| S | EX-01, EX-11 | | Disponibilité | EX-02, EX-07 |
| T | EX-03, EX-04, EX-09, EX-10, EX-11 | | Intégrité | EX-01, EX-03, EX-04, EX-06, EX-08, EX-09, EX-10, EX-11 |
| R | EX-07 | | Confidentialité | EX-04, EX-05, EX-11 |
| I | EX-05 | | Preuve | EX-07 |
| D | EX-02, EX-07 | | | |
| E | EX-06, EX-08, EX-10, EX-11 | | | |

**Aucune exigence sans test, aucune lettre STRIDE ni propriété DICP sans exigence.**

## Rejouer la traçabilité

```bash
python -m pytest tests/test_adapters.py tests/test_domain.py tests/test_services.py -q
python -m pytest tests/test_hexagon_abuse.py tests/test_creational_abuse.py -q
python -m pytest -m lab -q
```
