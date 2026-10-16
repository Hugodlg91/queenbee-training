# ADR 0006 — Faille 5 : l'autorisation se vérifie dans le cas d'usage

- **Statut** : accepté — 16/10/2026 · **Couche** : application · **STRIDE** : E, R · **DICP** : I, P
- **Contexte** : `close_incident(user, id)` fermait l'incident sans regarder qui demande : un compte sans rôle
  efface une attaque en cours de la vue du SOC.
- **Décision** : le cas d'usage reçoit un `Principal` et suit toujours l'ordre **autoriser → vérifier →
  règle métier → persister** ; le contrôle n'est pas laissé à l'interface (qu'un autre client pourrait contourner).
  Même règle dans `src/` : `IncidentService.move`.
- **Conséquences** : + aucun chemin d'appel n'échappe au contrôle ; − chaque appelant doit fournir une identité
  authentifiée (un `Principal`), ce qui impose une authentification en amont (MFA côté interface analyste).
- **Preuve** : `tests/test_lab_review.py::test_faille5_only_an_analyst_can_close`,
  `tests/test_hexagon_abuse.py::test_abuse_unauthorized_move_touches_nothing`
