# Tranche verticale : « on ne ferme pas un incident sans l'avoir trié, et seul un analyste le peut »

Une tranche verticale suit **une seule règle métier** à travers toutes les couches, du cœur
jusqu'au test qui la prouve. Ici : changer le statut d'un incident.

| Couche | Fichier | Ce qu'elle fait pour cette règle |
|---|---|---|
| **Gestion** (règle métier) | `src/queenbee/domain/model.py` | `Incident.transition_to` consulte une table des transitions (`_TRANSITIONS`) : OPEN → TRIAGED → (CONTAINED) → CLOSED. Tout le reste lève `DomainError`. C'est le pattern **État**. |
| **Contrat d'interface** | `src/queenbee/application/services.py`, `application/ports.py` | `IncidentService.move(who: Principal, incident_id: UUID, to: IncidentStatus) -> Incident`. Il ne dépend que du port `IncidentRepository` (un `Protocol`) et lève `AccessDeniedError` ou `DomainError`. |
| **Ordre du cas d'usage** | `services.py::IncidentService.move` | 1. **autoriser** (rôle `analyst`) → 2. **vérifier** (l'incident existe) → 3. **règle métier** (`transition_to`) → 4. **persister** (`save`). Refuser avant de lire : un intrus n'apprend même pas si l'incident existe. |
| **Persistance** | `src/queenbee/adapters/outbound/repositories.py` | `SqliteIncidentRepository.save` : `UPDATE incident SET status = ? WHERE id = ?` (paramétré). À la relecture, l'incident est reconstruit **et revalidé** : une ligne altérée en base lève `DomainError`. |
| **Restitution** | `src/queenbee/application/access.py`, `bootstrap.py` | `IncidentReadProxy.list_open()` renvoie des **copies** à un `viewer` ou `analyst` ; la façade `QueenBee.open_incidents()` sert l'affichage. |
| **Recette** (tests) | `tests/` | voir ci-dessous |

## Recette : les tests qui prouvent la règle

| Test | Ce qu'il vérifie |
|---|---|
| `tests/test_domain.py::test_state_forbids_skipping_triage` | OPEN → CLOSED refusé ; OPEN → TRIAGED → CLOSED accepté |
| `tests/test_defensive_patterns.py::test_abuse_forbidden_transition_refused` | toutes les transitions interdites sont refusées et le statut ne bouge pas |
| `tests/test_services.py::test_analyst_moves_incident` | un analyste fait avancer l'incident ; un identifiant inconnu est refusé |
| `tests/test_services.py::test_abuse_viewer_cannot_close_incident` | un `viewer` est refusé et l'incident reste OPEN |
| `tests/test_hexagon_abuse.py::test_abuse_unauthorized_move_touches_nothing` | refus **avant** toute lecture ou écriture dans le dépôt (0 lecture, 0 sauvegarde) |
| `tests/test_hexagon_abuse.py::test_abuse_forbidden_transition_is_not_persisted` | une transition interdite n'est jamais sauvegardée |
| `tests/test_creational_abuse.py::test_tampered_row_is_rejected_on_read` | une ligne modifiée directement en base est rejetée à la relecture |

Lancer la recette :

```bash
python -m pytest -k "transition or moves_incident or viewer_cannot or touches_nothing or tampered" -q
```
