# ADR 0001 — Architecture hexagonale : le domaine ne dépend de rien

- **Statut** : accepté — 14/10/2026
- **Décideurs** : Corentin, Hugo, Praveen, Ugo

## Contexte
Queen Bee reçoit des données **non fiables** : lignes de journaux et messages d'agents (frontière TB1),
dont certains champs sont choisis par l'attaquant (nom d'utilisateur d'un `Failed password`, IP forgée).
Le script hérité `legacy/log_watcher.py` mélangeait lecture, détection, SQL et SMTP dans une seule classe :
- le SQL construit par f-string ouvrait une injection (TB2) ;
- le mot de passe SMTP était en dur dans le code ;
- impossible de tester la détection sans vraie base et vrai serveur mail.

Il faut pouvoir valider les règles métier seules, changer de base ou de canal d'alerte sans toucher
à la détection, et rendre la frontière de confiance visible dans le code.

## Décision
Architecture hexagonale (ports et adaptateurs) en quatre couches, dépendances uniquement vers l'intérieur :
`bootstrap` → `adapters` → `application` → `domain`.
- `domain/` : `SecurityEvent`, `Alert`, `Incident`, règles ; aucun import technique (ni sqlite3, ni smtplib).
- `application/` : cas d'usage (`DetectionService`) et **ports** en `typing.Protocol`
  (`IncidentRepository`, `Notifier`).
- `adapters/` : implémentations des ports (SQLite paramétré, notifiers).
- `bootstrap.py` : seule racine de composition (`build_app`), qui crée et relie les objets.

Le contrat est vérifié automatiquement par `import-linter` (`PYTHONPATH=src lint-imports`).

## Alternatives écartées
1. **Garder un script unique refactoré en fonctions** : plus court, mais la détection reste couplée
   à SQLite et SMTP ; impossible de tester les règles sans effets de bord, et rien n'empêche un futur
   commit de remettre du SQL dans la logique métier.
2. **Architecture MVC / framework web (Django, Flask) d'emblée** : le modèle serait lié à l'ORM ;
   la validation des données non fiables serait dispersée entre formulaires, vues et modèles ; surface
   d'attaque et dépendances (donc vulnérabilités `pip-audit`) bien plus grandes pour un besoin sans UI.
3. **Couches classiques (présentation → métier → données)** : le métier dépend de la couche données,
   donc de SQLite ; on ne peut pas remplacer la base par une version mémoire dans les tests.

## Conséquences
- **+** Les règles et objets du domaine se testent sans base ni réseau (`tests/test_domain.py`).
- **+** Un objet du domaine invalide ne peut pas exister : la validation des entrées non fiables
  est faite une fois, à la construction.
- **+** Changer de stockage ou de canal d'alerte = un nouvel adaptateur, sans toucher au domaine
  (fabrique abstraite `ProdFactory` / `InMemoryFactory`).
- **+** Une inversion de couche fait échouer `make check` (import-linter).
- **−** Plus de fichiers et d'indirections qu'un script : il faut connaître le découpage pour s'y retrouver.
- **−** Les données traversent plusieurs conversions (ligne → `SecurityEvent` → `Alert` → `Incident` → ligne SQL).
- **−** Les ports `Protocol` sont vérifiés par mypy, pas à l'exécution : sans `mypy --strict`, une
  implémentation incomplète passerait inaperçue jusqu'à l'appel.

## Menaces STRIDE traitées
- **T** (altération) sur TB1 · Intégrité : `SecurityEvent` figé et validé (IP, nom, action, fuseau).
- **T / I** sur TB2 · Intégrité, Confidentialité : SQL paramétré, isolé dans `SqliteIncidentRepository`.
- **I** (fuite) sur TB5 · Confidentialité : secret lu dans l'environnement, `repr=False`, jamais dans le domaine.
- **E** (élévation) sur TB5 · Intégrité : la fabrique de règles n'accepte que les noms enregistrés
  (pas de `getattr` / `importlib` sur une chaîne venue de la config).

## Preuve
- `tests/test_domain.py::test_invalid_event_cannot_exist`
- `tests/test_domain.py::test_factory_rejects_unknown_rule`
- `tests/test_creational.py::test_service_runs_with_any_family`
- `tests/test_services.py::test_sqlite_repo_resists_injection` (J2)
- `PYTHONPATH=src lint-imports` : contrat « Architecture hexagonale : les dépendances pointent vers le domaine » KEPT
