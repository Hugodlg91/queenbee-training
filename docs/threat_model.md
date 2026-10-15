# Modèle de menaces — Queen Bee

> Atelier J1-A1 · méthode : actifs → acteurs → DFD et frontières → STRIDE par flux → exigences testables.
> DICP = **D**isponibilité, **I**ntégrité, **C**onfidentialité, **P**reuve.

## 1. Actifs

| # | Actif | Pourquoi il compte | D | I | C | P |
|---|---|---|---|---|---|---|
| A1 | Événements de sécurité remontés par les agents | matière première de la détection : un faux événement crée un faux incident, un événement supprimé masque une attaque | x | x | | x |
| A2 | Incidents (base `queenbee.db`) | preuve de l'attaque et pilotage de la réponse ; contiennent IP et comptes visés | x | x | x | x |
| A3 | Clé HMAC des agents (`QUEENBEE_AGENT_KEY`) | qui la possède peut injecter de faux événements au nom de n'importe quel agent | | | x | |
| A4 | Règles de détection et leurs seuils | un attaquant qui les modifie (seuil à 10⁶, règle supprimée) devient invisible ; une règle chargée par nom arbitraire = exécution de code | | x | | |
| A5 | Canal d'alerte vers le SOC (notifications) | sans lui, personne ne réagit ; saturé, il noie les vraies alertes | x | x | | |
| A6 | Liste de blocage du pare-feu | une IP légitime bloquée = déni de service auto-infligé ; un blocage annulé = attaquant libre | x | x | | x |
| A7 | Journal d'audit (qui a fait quoi sur un incident) | seule preuve en cas de contestation d'une action d'analyste | | x | | x |
| A8 | Renseignement sur les menaces (flux externe, ajouté au J2) | un faux indicateur fait bloquer une IP légitime ou ignorer une vraie | | x | | |

## 2. Acteurs

| Acteur | Légitime ? | Ce qu'il peut faire / vouloir |
|---|---|---|
| Agent (« abeille ») | oui | envoie des événements signés depuis un hôte surveillé |
| Analyste SOC | oui | lit, trie, ferme les incidents ; déclenche un blocage |
| Lecteur (viewer) | oui, limité | consulte seulement |
| Administrateur | oui | configure règles, seuils, secrets |
| Fournisseur du flux de menaces (J2) | partiellement | données utiles, mais format et contenu qu'on ne contrôle pas |
| Attaquant externe | non | forge des lignes de log / messages d'agent, flood, injection (SQL, regex, nom de règle) |
| **Agent compromis** | *semblait légitime, ne l'est plus* | possède une vraie clé : envoie des événements bien signés mais mensongers ou en masse |
| Analyste malveillant ou compte volé | *semblait légitime* | ferme un incident sans triage, nie l'avoir fait |

## 3. Diagramme de flux de données (DFD) et frontières de confiance

```
                         TB1                         TB2
 [Hôte surveillé]  ┊                           ┊
  (Agent) ──F1 lignes sshd / message signé──▶ (Ingestion : parse + HMAC + validation)
                   ┊                                │ F2 SecurityEvent valides
                   ┊                                ▼
                   ┊                       (Détection : RuleSet) ──F3 Incident──▶ [[Base incidents]]
                   ┊                                │                        ┊
                   ┊                                │ F4 Alert               ┊
                                                    ▼                  TB3
 (Analyste SOC) ──F6 lire / trier / fermer──▶ (Service incidents) ┊──F4──▶ (Notifier SMTP → SOC)
             TB4 ┊                                  │                ┊
                                                    └──F5 bloquer IP─┊──▶ (Pare-feu)
 (Admin) ──F7 .env / règles──▶ (Démarrage : Builder Settings + Factory de règles)
       TB5 ┊
 (Flux de menaces) ──F8 indicateurs──▶ (Couche anti-corruption : ThreatFeedTranslator)
                TB6 ┊
```

| Frontière | Sépare | Justification |
|---|---|---|
| **TB1** | réseau des agents ↔ API d'ingestion | tout ce qui arrive d'un hôte surveillé peut avoir été écrit par l'attaquant (le nom d'utilisateur d'un `Failed password` est choisi par lui) |
| **TB2** | application ↔ base de données | le moteur SQL interprète du texte : une donnée non fiable y devient du code (injection) |
| **TB3** | application ↔ systèmes externes (SMTP, pare-feu) | actions à effet réel ; une commande pare-feu construite par chaîne = injection de commande |
| **TB4** | analystes ↔ service incidents | change de niveau de privilège : chaque appel doit porter une identité et un rôle |
| **TB5** | administrateur / environnement ↔ démarrage | les secrets et la configuration entrent ici ; une valeur mal formée ne doit pas démarrer l'appli |
| **TB6** (J2) | fournisseur de renseignement ↔ reine | format et vocabulaire d'un tiers : ils ne doivent pas pénétrer le domaine (couche anti-corruption) |

## 4. STRIDE par flux traversant une frontière

| Flux | S usurpation | T altération | R répudiation | I fuite | D déni de service | E élévation | Exigences |
|---|---|---|---|---|---|---|---|
| F1 Agent → Ingestion (TB1) | faux agent sans clé | message modifié en route ; champ ajouté (`is_admin`) | agent qui nie avoir envoyé | | flood de lignes, ligne de 10 Mo, regex à backtracking (ReDoS) | | EX-01, EX-02, EX-03 |
| F3 Détection → Base (TB2) | | injection SQL via IP / nom d'utilisateur | | dump de la table par injection | | requête arbitraire = droits du compte BDD | EX-04 |
| F4 Alert → SOC (TB3) | | | | IP / comptes dans un mail non chiffré | tempête d'alertes qui noie le SOC | | EX-07 |
| F5 Blocage → Pare-feu (TB3) | | IP piégée `1.2.3.4; iptables -F` | blocage non tracé | | blocage d'IP légitime | injection de commande système | EX-08 |
| F6 Analyste → Incidents (TB4) | compte volé | incident fermé sans triage | analyste qui nie la fermeture | lecture par un compte sans rôle | | viewer qui ferme un incident | EX-06, EX-07 |
| F8 Flux de menaces → ACL (TB6, J2) | faux fournisseur | indicateur piégé (`evil.com`, `1.2.3.4/0`), niveau inconnu | | | flux énorme | indicateur qui ferait bloquer une IP interne | EX-09 |
| F2' Agent compromis → Ingestion (TB1, J2) | vraie clé, faux contenu | message signé mais mal formé, champ en trop ou dupliqué | | | | `is_admin` ajouté au message | EX-10 |
| F7 Admin → Démarrage (TB5) | | règle chargée par nom arbitraire (`__import__('os')`), seuil `True` | | clé affichée dans `print(settings)` / les logs | appli démarrée sans clé | exécution de code via la config | EX-05, EX-03 |

Menaces écartées (non crédibles dans le périmètre) : attaque physique sur les hôtes, compromission du système d'exploitation de la reine.

## 5. Exigences de sécurité (testables)

```
EX-01  Tout message d'agent DOIT porter une signature HMAC-SHA256 valide, vérifiée en temps constant ;
       un message signé avec une autre clé DOIT être rejeté (UnauthenticatedError).
       Menace : S sur TB1 · Propriété : Intégrité (authenticité)
       Preuve : tests/test_adapters.py::test_abuse_forged_signature_rejected

EX-02  Toute ligne de journal piégée DOIT être rejetée (DomainError),
       et 1 000 lignes piégées DOIVENT être traitées en moins de 1 s.
       Menace : D sur TB1 · Propriété : Disponibilité
       Preuve : tests/test_adapters.py::test_parser_is_fast_on_adversarial_input

EX-03  Un SecurityEvent DOIT être refusé à la construction si l'IP n'est pas une adresse IP valide,
       si le nom d'utilisateur sort de [A-Za-z0-9._-]{1,64}, si l'action est hors liste blanche
       ou si l'horodatage n'a pas de fuseau ; une fois créé, il DOIT être non modifiable.
       Menace : T sur TB1 · Propriété : Intégrité
       Preuve : tests/test_domain.py::test_invalid_event_cannot_exist,
                tests/test_domain.py::test_event_is_immutable

EX-04  Toute écriture et lecture en base DOIT utiliser des requêtes paramétrées ;
       un nom d'utilisateur contenant `'; DROP TABLE` DOIT être stocké tel quel sans effet.
       Menace : T sur TB2 · Propriété : Intégrité, Confidentialité
       Preuve : tests/test_services.py::test_sqlite_repo_resists_injection,
                tests/test_creational_abuse.py::test_sqlite_stores_hostile_text_verbatim

EX-05  La clé HMAC DOIT être lue dans l'environnement, faire au moins 32 octets,
       et ne DOIT jamais apparaître dans repr()/str() de la configuration ;
       sans clé valide, l'application DOIT refuser de démarrer (ConfigError).
       Menace : I sur TB5 · Propriété : Confidentialité
       Preuve : tests/test_adapters.py::test_secret_never_printed,
                tests/test_adapters.py::test_missing_secret_refuses_to_start,
                tests/test_creational_abuse.py::test_secret_never_in_repr_or_str

EX-06  Seul un principal portant le rôle « analyst » DOIT pouvoir changer le statut d'un incident,
       et un incident NE DOIT PAS passer de OPEN à CLOSED sans l'état TRIAGED.
       Menace : E sur TB4 · Propriété : Intégrité
       Preuve : tests/test_services.py::test_abuse_viewer_cannot_close_incident,
                tests/test_domain.py::test_state_forbids_skipping_triage

EX-07  Toute alerte notifiée DOIT être journalisée (logger queenbee.audit, nom de règle et IP),
       et au plus N alertes par fenêtre DOIVENT partir vers le SOC (le surplus est compté, pas envoyé).
       Menace : R et D sur TB3 · Propriété : Preuve, Disponibilité
       Preuve : tests/test_services.py::test_audit_decorator_logs,
                tests/test_services.py::test_abuse_rate_limiter_absorbs_alert_flood

EX-08  Une règle DOIT être créée uniquement depuis un nom présent dans le registre de la fabrique
       (jamais getattr/importlib sur une chaîne) avec un seuil entier strictement positif (bool refusé) ;
       une commande de blocage DOIT refuser toute cible qui n'est pas une adresse IP.
       Menace : E sur TB5 et TB3 · Propriété : Intégrité
       Preuve : tests/test_domain.py::test_factory_rejects_unknown_rule,
                tests/test_domain.py::test_factory_rejects_bool_threshold,
                tests/test_services.py::test_command_undo

EX-09  (J2) Tout indicateur venu du flux de menaces DOIT passer par la couche anti-corruption :
       un indicateur qui n'est pas une adresse IP ou un niveau de risque inconnu DOIT être rejeté (DomainError),
       et le score DOIT rester dans [0, 100].
       Menace : T sur TB6 · Propriété : Intégrité
       Preuve : tests/test_adapters.py::test_anti_corruption_layer_translates_and_rejects,
                tests/test_hexagon_abuse.py::test_abuse_threat_feed_garbage_rejected

EX-10  (J2) Un message correctement signé (agent compromis) DOIT quand même être rejeté s'il a un champ
       en trop, manquant, dupliqué, non textuel ou une valeur invalide pour le domaine.
       Menace : T et E sur TB1 · Propriété : Intégrité
       Preuve : tests/test_adapters.py::test_abuse_extra_field_rejected,
                tests/test_hexagon_abuse.py::test_abuse_signed_but_malformed_message_rejected
```

### Couverture

| STRIDE | Exigences |
|---|---|
| S | EX-01 |
| T | EX-03, EX-04, EX-09, EX-10 |
| R | EX-07 |
| I | EX-05 |
| D | EX-02, EX-07 |
| E | EX-06, EX-08, EX-10 |

État au rendu J2 : toutes les preuves citées sont vertes (`make check` vert).
