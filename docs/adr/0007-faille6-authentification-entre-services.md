# ADR 0007 — Faille 6 : les services s'authentifient entre eux

- **Statut** : accepté — 16/10/2026 · **Couche** : infrastructure · **STRIDE** : S, I · **DICP** : C, I
- **Contexte** : le service d'enrichissement répondait à tout processus du réseau, sans jeton ni certificat :
  un poste compromis dans le réseau interne interroge ou usurpe n'importe quel service (« il n'est pas exposé »).
- **Décision** : chaque appel porte une signature HMAC-SHA256 calculée avec la **clé du service appelé**
  (ADR 0002), vérifiée en temps constant **avant** de répondre ; l'entrée est ensuite validée. En production,
  **mTLS** entre services en plus (chaque service a son certificat) : voir le document d'infrastructure.
- **Conséquences** : + un appel sans la bonne clé est refusé, une signature ne vaut que pour sa requête ;
  − une clé et un certificat de plus par service à distribuer et à renouveler ; sans horodatage signé,
  une requête identique peut être rejouée (risque accepté : la réponse est en lecture seule).
- **Preuve** : `tests/test_lab_review.py::test_faille6_unauthenticated_caller_refused`,
  `::test_faille6_other_service_key_refused`
