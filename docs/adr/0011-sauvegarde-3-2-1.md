# ADR 0011 — Sauvegarde 3-2-1 avec copie immuable, RPO 15 min, RTO 4 h

- **Statut** : accepté — 16/10/2026 · **Couche** : infrastructure · **STRIDE** : D, T · **DICP** : D, I
- **Contexte** : la base des incidents est la preuve et le pilotage de la réponse ; une panne, une erreur ou un
  rançongiciel ne doit pas faire perdre plus de 15 minutes d'incidents ni arrêter le SOC plus de 4 heures.
- **Décision** : sauvegarde toutes les 15 minutes, règle **3-2-1** (3 copies, 2 supports, 1 hors site
  **immuable**) ; restauration testée **chaque mois** dans un environnement isolé, durée et perte mesurées.
- **Conséquences** : + reprise prouvée, pas supposée ; + la copie immuable résiste à un attaquant qui détient
  l'application ; − coût de stockage et d'un exercice mensuel ; − avec SQLite, la sauvegarde à chaud demande
  l'API de sauvegarde SQLite (ou une base serveur au-delà du pilote).
- **Preuve** : `docs/exploitation_securite.md` §3 (objectifs chiffrés et scénario de test de reprise)
