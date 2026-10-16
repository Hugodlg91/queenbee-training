# ADR 0010 — Journaux immuables, hors de portée de l'application

- **Statut** : accepté — 16/10/2026 · **Couche** : infrastructure · **STRIDE** : R, T · **DICP** : P, I
- **Contexte** : un attaquant qui prend le contrôle du cœur voudra effacer ses traces ; si les journaux sont
  sur le même serveur ou modifiables par l'application, la preuve disparaît avec lui.
- **Décision** : le cœur **envoie** ses journaux (syslog TLS, flux F4) vers un collecteur en zone Sécurité (Z5),
  en écriture seule ; stockage immuable (WORM), UTC, 1 an ; aucun secret ni contenu brut rejeté n'est journalisé.
- **Conséquences** : + la preuve survit à la compromission de l'application ; − un service de plus à exploiter
  et à dimensionner ; − si le collecteur est injoignable, les événements doivent être mis en tampon localement
  (risque de perte bornée à prévoir).
- **Preuve** : `docs/exploitation_securite.md` §2 ; `tests/test_services.py::test_audit_decorator_logs`
  (chaque alerte produit une trace d'audit)
