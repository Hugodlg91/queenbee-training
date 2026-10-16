# ADR 0004 — Faille 3 : des données, jamais du code (fin de pickle)

- **Statut** : accepté — 16/10/2026 · **Couche** : adaptateur d'entrée · **STRIDE** : T, E · **DICP** : I
- **Contexte** : `pickle.loads(raw)` sur un message d'agent exécute le code choisi par l'expéditeur
  **pendant la lecture** (`__reduce__`) : exécution de code à distance avec les droits de la reine.
- **Décision** : JSON uniquement (`json.loads`), taille ≤ 4 Kio, schéma strict (exactement 4 champs textuels),
  puis construction d'un `SecurityEvent` validé par le domaine. Dans `src/`, l'API agents ajoute la signature HMAC
  vérifiée **avant** de lire (`agent_api.py`).
- **Conséquences** : + aucune donnée reçue ne peut s'exécuter ; − le format est rigide : tout nouveau champ
  impose de faire évoluer le schéma et les agents en même temps.
- **Preuve** : `tests/test_lab_vulnerable.py::test_faille3_pickle_payload_rejected_without_running`,
  `tests/test_hexagon_abuse.py::test_abuse_signed_but_malformed_message_rejected`
