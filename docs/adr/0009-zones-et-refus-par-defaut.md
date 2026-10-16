# ADR 0009 — Cloisonnement en zones, refus par défaut

- **Statut** : accepté — 16/10/2026 · **Couche** : infrastructure · **STRIDE** : S, T, E, D · **DICP** : C, I, D
- **Contexte** : les agents (Z1) et les analystes (Z7) sont des entrées non ou peu fiables ; le cœur détient
  la clé HMAC et la logique ; un réseau « à plat » laisserait un hôte compromis joindre directement la base
  ou le cœur.
- **Décision** : 7 zones par niveau de confiance (`docs/infrastructure.md`) ; seuls les 12 flux de la matrice
  sont ouverts, chacun justifié par un élément d'architecture ; **tout le reste est refusé et journalisé**.
  Seule la DMZ (proxy inverse TLS) est joignable de l'extérieur ; mTLS entre zones internes.
- **Conséquences** : + un hôte compromis n'atteint que le proxy, qui filtre ; + un nouveau flux exige une
  décision écrite ; − plus d'équipements et de règles à maintenir (pare-feu entre zones, PKI pour mTLS) ;
  − chaque nouveau besoin réseau ralentit (il faut mettre à jour la matrice).
- **Preuve** : `docs/infrastructure.md` §2 (matrice, dernière ligne « tout le reste refusé ») et §3 (complétude)
