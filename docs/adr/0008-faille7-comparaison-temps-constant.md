# ADR 0008 — Faille 7 : secrets comparés en temps constant

- **Statut** : accepté — 16/10/2026 · **Couche** : sécurité (transverse) · **STRIDE** : S, I · **DICP** : C
- **Contexte** : `token == API_KEY` s'arrête au premier caractère différent : en mesurant le temps de réponse
  sur de nombreux essais, un attaquant devine le jeton caractère par caractère.
- **Décision** : toute comparaison de secret (jeton, signature HMAC) passe par `hmac.compare_digest`, dont
  le temps ne dépend pas de la position de l'erreur ; un type inattendu est refusé, jamais comparé.
  Même règle dans `src/` : `agent_api.parse_agent_message`.
- **Conséquences** : + plus de fuite par le temps ; − la règle est facile à oublier dans du nouveau code :
  elle est vérifiée par test (jeton espion) et doit être rappelée en revue de code.
- **Preuve** : `tests/test_lab_review.py::test_faille7_token_compared_in_constant_time`,
  `tests/test_adapters.py::test_abuse_forged_signature_rejected`
