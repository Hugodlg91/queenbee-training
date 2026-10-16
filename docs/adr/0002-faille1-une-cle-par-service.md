# ADR 0002 — Faille 1 : une clé par service, injectée au démarrage

- **Statut** : accepté — 16/10/2026 · **Couche** : configuration · **STRIDE** : S, I · **DICP** : C
- **Contexte** : `API_KEY = "qb-admin-2026"` était écrite dans le code et partagée par tous les services :
  quiconque lit le dépôt (ou son historique) possède la clé de tous les services.
- **Décision** : une clé par service (`QUEENBEE_<SERVICE>_KEY`, ≥ 32 octets, hexadécimal), lue dans
  l'environnement au démarrage, **sans valeur par défaut** ; service inconnu ou clé faible = refus de démarrer.
- **Conséquences** : + une clé volée n'ouvre qu'un service ; − il faut distribuer et faire tourner une clé
  par service (coffre de secrets) ; l'ancienne valeur reste dans l'historique Git : elle est **révoquée**, pas effacée.
- **Preuve** : `tests/test_lab_review.py::test_faille1_no_hardcoded_secret_one_key_per_service`,
  `::test_faille1_missing_or_weak_key_refused`
