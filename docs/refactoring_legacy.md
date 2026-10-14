# Refactoring de `legacy/log_watcher.py` — relevé des problèmes (atelier J1-A2)

Filet posé avant de toucher au code : `tests/test_legacy_characterization.py`
(5 échecs depuis la même IP → une seule alerte ; échecs dispersés → rien).

| # | Ligne | Problème (SOLID ou sécurité) | Conséquence | Correction (où) |
|---|---|---|---|---|
| 1 | 10 `SMTP_PASSWORD = "Sup3rS3cret!"` | **Sécu** : secret en dur, versionné (CWE-798) | quiconque lit le dépôt ou son historique a le mot de passe ; rotation impossible sans commit | secret lu dans l'environnement, `field(repr=False)`, refus de démarrer sans lui (`config.py`, `settings_from_env`) |
| 2 | 11 `DB = sqlite3.connect(...)` | **D** (inversion des dépendances) + état global (Singleton implicite) | connexion ouverte à l'import, fichier créé dans le répertoire courant ; impossible de tester sans vraie base ; tous les tests partagent l'état | port `IncidentRepository` (Protocol) reçu par le constructeur ; création dans `bootstrap.build_app` (`application/ports.py`, `factories.py`) |
| 3 | 13 `class LogWatcher` | **S** (responsabilité unique) : lit, parse, compte, stocke, alerte, formate | chaque changement (nouveau format, autre base) touche la même classe ; impossible de tester une partie seule | `SecurityEvent` (domaine), `BruteForceRule` (détection), `DetectionService` (orchestration), dépôts et notifiers (adaptateurs) |
| 4 | 19 `for line in open(self.path)` | **Sécu** : fichier jamais fermé, aucune limite de taille de ligne | fuite de descripteurs ; une ligne de 1 Go épuise la mémoire (D de STRIDE) | lecture côté adaptateur d'entrée avec `with` et longueur bornée (J2 `log_parser`) ; le domaine borne déjà chaque champ |
| 5 | 20 `re.search(r"Failed password for (.*) from (.*)")` | **Sécu** : regex non ancrée, `.*` gourmand | `from 10.0.0.66 OR 1=1` est capturé comme « IP » ; un nom d'utilisateur `x from 1.2.3.4` déplace l'attribution | regex ancrée et bornée (`fullmatch`, `[A-Za-z0-9._-]{1,64}`) + IP validée par `ipaddress` dans `SecurityEvent.__post_init__` |
| 6 | 21–22 `user, ip = m.group(...)` | **Sécu** : aucune validation des données venues de l'attaquant | n'importe quel texte entre dans le compteur, la base et le mail | objet-valeur `SecurityEvent` figé, invalide = impossible à construire (`domain/model.py`) |
| 7 | 26 `DB.execute(f"INSERT ... '{ip}'")` | **Sécu** : injection SQL (CWE-89) | `ip` vient du log donc de l'attaquant : `x'); DROP TABLE incidents;--` | requête paramétrée `execute("... VALUES (?, ?)", (...))` (`SqliteIncidentRepository`) |
| 8 | 24 `if self.counts[ip] == 5` | **O** (ouvert-fermé) : seuil et règle codés en dur | ajouter une règle (scan de ports) = modifier la classe ; seuil non configurable | Strategy `Rule` + Composite `RuleSet` + Factory `build_rule` (`domain/rules.py`) |
| 9 | 29–32 `alert()` crée `smtplib.SMTP("mail.local")` | **D** + **Sécu** : dépendance concrète, SMTP sans TLS, pas de limite | impossible de tester sans serveur mail ; mot de passe envoyé en clair ; tempête d'alertes possible | port `Notifier` (Protocol), `MemoryNotifier` / `LoggingNotifier` choisis par une fabrique abstraite (`factories.py`) |
| 10 | 34–40 `report(kind)` `if/elif` | **O** + **I** : chaque format = un `elif` de plus dans la classe qui détecte | la classe grossit sans fin ; le format HTML est vulnérable au XSS (IP non échappée) | hors périmètre J1 : un formateur par format (Strategy), échappement HTML ; à faire au J2 côté adaptateurs |
| 11 | 15–16 `self.counts = {}` | **Sécu** : compteur qui ne se vide jamais, clé = texte non validé | mémoire non bornée (une clé par « IP » inventée) | comptage sur un lot d'événements validés dans `BruteForceRule.evaluate`, sans état global |
| 12 | partout | pas de types, pas de tests | régressions invisibles | `mypy --strict`, `tests/test_domain.py`, tests de caractérisation |

## Correspondance avec le nouveau code

| Avant | Après |
|---|---|
| `LogWatcher.run` (comptage + seuil) | `domain/rules.py::BruteForceRule.evaluate` |
| tuple `(user, ip)` brut | `domain/model.py::SecurityEvent` (figé, validé) |
| `DB.execute(f"...")` | `adapters/outbound/repositories.py::SqliteIncidentRepository` |
| `alert()` SMTP | port `Notifier` + `adapters/outbound/notifiers.py` |
| `SMTP_PASSWORD`, `DB` globaux | `config.py` (Builder) + `bootstrap.py::build_app` (racine de composition) |

L'équivalence est vérifiée par `tests/test_legacy_characterization.py::test_new_domain_matches_legacy_behaviour`.
