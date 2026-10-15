# Parcours utilisateur : d'« attaque détectée » à « incident clos »

Scénario : un attaquant essaie des mots de passe sur le compte `root` d'un serveur surveillé
(10.0.0.66). Queen Bee détecte la force brute, un analyste trie l'incident, bloque l'IP puis ferme l'incident.

| # | Étape | Composante (code) | Frontière | Menace STRIDE | Contrôle en place | Preuve (test) |
|---|---|---|---|---|---|---|
| 1 | L'attaquant échoue 5 fois ; `sshd` écrit `Failed password for root from 10.0.0.66` | hôte surveillé (hors Queen Bee) | — | **S** : le nom d'utilisateur de la ligne est choisi par l'attaquant | aucune confiance accordée au contenu de la ligne | — |
| 2 | L'agent signe le message (HMAC-SHA256) et l'envoie à la reine | `adapters/inbound/agent_api.py::parse_agent_message` | **TB1** réseau agents → reine | **S** faux agent · **T** message altéré · **D** messages énormes | taille ≤ 4 Kio vérifiée d'abord, signature comparée en temps constant, schéma JSON strict | `test_abuse_forged_signature_rejected`, `test_abuse_tampered_body_rejected` |
| 3 | Chaque ligne devient un `SecurityEvent` validé | `adapters/inbound/log_parser.py::parse_sshd_line` → `domain/model.py::SecurityEvent` | TB1 (suite) | **T** ligne piégée (`10.0.0.66 OR 1=1`, `<script>`) · **D** ReDoS | longueur bornée avant la regex, `fullmatch`, objet figé revalidé par le domaine | `test_malicious_lines_rejected`, `test_parser_is_fast_on_adversarial_input` |
| 4 | Les règles détectent la force brute ; un incident OPEN est enregistré | `domain/rules.py::RuleSet` → `application/services.py::DetectionService` → `SqliteIncidentRepository` | **TB2** application → base | **T** / **I** injection SQL via l'IP ou le nom | requêtes paramétrées, relecture revalidée | `test_detection_creates_incident_and_notifies`, `test_sqlite_repo_resists_injection` |
| 5 | Le SOC est prévenu | `AuditedNotifier` → `RateLimitedNotifier` → notifier | **TB3** application → SOC | **R** alerte niée · **D** tempête d'alertes | chaque alerte est journalisée (`queenbee.audit`), au plus N par fenêtre, le surplus est compté | `test_audit_decorator_logs`, `test_abuse_rate_limiter_absorbs_alert_flood` |
| 6 | L'analyste consulte les incidents ouverts | `application/access.py::IncidentReadProxy` | **TB4** analyste → service | **I** lecture sans rôle · **T** le lecteur modifie ce qu'il lit | rôle `viewer`/`analyst` vérifié à chaque appel, copies renvoyées | `test_proxy_blocks_principal_without_role`, `test_abuse_reader_cannot_modify_what_it_reads` |
| 7 | L'analyste passe l'incident en TRIAGED | `IncidentService.move` (autoriser → vérifier → règle → persister) | TB4 | **E** un `viewer` tente de changer le statut | contrôle du rôle `analyst` en étape 1, avant toute lecture | `test_abuse_viewer_cannot_close_incident`, `test_abuse_unauthorized_move_touches_nothing` |
| 8 | Il bloque l'IP au pare-feu, puis ferme l'incident (CLOSED) | `adapters/outbound/response.py::BlockIpCommand` + `CommandHistory` ; `Incident.transition_to` | **TB3** application → pare-feu | **E** / **T** injection de commande (`10.0.0.66; iptables -F`) · **R** blocage non tracé | IP validée dans le constructeur, commande journalisée et annulable ; fermeture impossible sans triage | `test_command_undo`, `test_abuse_trapped_ip_never_reaches_firewall`, `test_state_forbids_skipping_triage` |

**Frontières traversées** : TB1, TB2, TB3 et TB4 (4 frontières, le minimum demandé est 2).
**Toutes les lettres STRIDE** apparaissent : S (2), T (2, 3, 4, 6, 8), R (5, 8), I (4, 6), D (2, 3, 5), E (7, 8).

> Limite du périmètre : l'interface de l'analyste (écran, API HTTP, authentification forte) n'est pas
> codée. Le parcours commence au cas d'usage, avec un `Principal` déjà authentifié.
