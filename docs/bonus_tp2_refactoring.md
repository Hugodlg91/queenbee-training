# Bonus J1-A2 — même démarche sur `tp2_log_parser.py` (Python Scripting Sécu)

Script d'origine : `legacy/tp2_log_parser.py` (copié tel quel). Échantillon : `tests/data/tp2_access.log`.
Nouveau code : `bonus/http_log_audit/`. Lancement :

```bash
python -m bonus.http_log_audit tests/data/tp2_access.log --threshold 3
```

## 1. Le filet

`tests/test_tp2_characterization.py` fige le comportement **avant** refactoring :

| Test | Ce qu'il fige |
|---|---|
| `test_legacy_sample_raises_bruteforce_and_sqli` | à conserver : 10.0.0.15 (4 × 401) → brute force ; 192.168.1.100 → SQLi |
| `test_legacy_two_failures_are_not_bruteforce` | à conserver : sous le seuil, rien |
| `test_legacy_bug_innocent_word_flagged_as_sqli` | défaut : `/forum` est une « injection » |
| `test_legacy_bug_response_size_401_counted_as_failure` | défaut : une réponse 200 de 401 octets compte comme un échec |
| `test_legacy_bug_url_encoded_injection_missed` | défaut : `1%27%20OR...` (ce qu'un serveur journalise vraiment) passe inaperçu |
| `test_legacy_bug_terminal_escape_printed_raw` | défaut : les séquences ANSI de l'attaquant sont envoyées au terminal de l'analyste |

## 2. Relevé des problèmes

| # | Ligne | Problème (SOLID ou sécurité) | Conséquence | Correction (où) |
|---|---|---|---|---|
| 1 | 4 `LOG_FILE = "access.log"` | **D** : chemin global en dur | impossible d'analyser un autre fichier sans modifier le code ; dépend du répertoire courant | chemin passé en argument (`cli.py`, argparse) |
| 2 | 6 `analyze_logs()` | **S** : une fonction lit, découpe, détecte 2 attaques et affiche | toute évolution touche tout ; rien n'est testable sans capturer `stdout` | `parser.py` (lecture) / `rules.py` (détection) / `ports.py` + `cli.py` (sortie) |
| 3 | 9 `(union\|select\|...\|or\|'\|1=1)` | **Sécu** : motif sans bornes de mot, sur la ligne entière | faux positifs massifs (`/forum`, `/order`, `error`) : le SOC ignore vite toutes les alertes | motifs avec `\b`, appliqués à la cible de la requête seulement (`SqlInjectionRule`) |
| 4 | 9 | **Sécu** : aucune normalisation | faux négatifs : `%27%20OR%20...`, `+OR+`, `UNION/**/SELECT` passent | décodage URL (`unquote_plus`, 2 passes bornées) puis repli des commentaires SQL avant détection |
| 5 | 11 `open(LOG_FILE, "r")` | **Sécu** : pas d'encodage, aucune limite de taille | un octet non UTF-8 fait planter toute l'analyse (D) ; une ligne de 1 Go est chargée en mémoire | `encoding="utf-8", errors="replace"`, ligne bornée à 8 Kio, ligne illisible = rejetée et comptée |
| 6 | 17 `ip = line_str.split()[0]` | **Sécu** : premier mot accepté sans validation | n'importe quel texte devient une « IP » et une clé du compteur | `ipaddress.ip_address` dans `HttpRequest.__post_init__` ; objet figé |
| 7 | 20 `" 401 " in line_str` | **Sécu** : statut cherché n'importe où | une taille de réponse de 401 octets, ou un User-Agent `" 401 "` choisi par l'attaquant, comptent comme échecs | regex ancrée du format CLF/combined ; `status` est un champ entier validé (100–599) |
| 8 | 25 `print(... {line_str})` | **Sécu** : ligne de l'attaquant recopiée telle quelle (CWE-150, CWE-117) | effacement d'écran, faux messages dans le terminal ou le journal de l'analyste | sortie neutralisée (`_safe`) : caractères de contrôle échappés, longueur tronquée |
| 9 | 25 | **Sécu** + **S** : une alerte par ligne | 10 000 requêtes piégées = 10 000 alertes (D sur l'analyste) | une alerte par IP, avec le nombre de requêtes et un exemple |
| 10 | 28 `if count >= 3` | **O** : seuil en dur | impossible d'ajuster sans modifier le code | `AuthBruteForceRule(threshold=…)` validé (entier, pas `bool`), option `--threshold` |
| 11 | 19–29 | **O** : chaque nouvelle détection = un `if` de plus dans la fonction | la fonction grossit sans fin | Strategy `Rule` + Composite `RuleSet` ; nouvelle règle = nouvelle classe |
| 12 | 25, 29 `print` | **D** + **I** : sortie couplée à la console | impossible d'envoyer les alertes ailleurs (fichier, SIEM) ou de les tester | port `FindingSink` (Protocol) ; `ConsoleSink` en est une implémentation |
| 13 | partout | pas de types, pas de tests, `if __name__` sans code retour | régressions invisibles ; un script appelant ne sait pas s'il y a eu des alertes | `mypy --strict`, tests, code de sortie 1 si une alerte, 2 si erreur |

## 3. Correspondance

| Avant | Après |
|---|---|
| `line_str.split()[0]`, `" 401 " in ...` | `bonus/http_log_audit/parser.py::parse_access_line` → `HttpRequest` validé |
| `failed_attempts[ip] += 1` + `count >= 3` | `rules.py::AuthBruteForceRule` |
| `sqli_pattern.search(line_str)` | `rules.py::SqlInjectionRule` (cible décodée, bornes de mot) |
| `print(...)` | port `FindingSink` + `cli.py::ConsoleSink` (sortie neutralisée) |
| `LOG_FILE` global | `cli.py::main(argv)` (racine de composition) |

L'équivalence sur l'échantillon d'origine est vérifiée par
`tests/test_tp2_refactored.py::test_same_findings_as_legacy_on_sample`, et chaque défaut figé
au §1 a son test inverse dans `tests/test_tp2_refactored.py`.
