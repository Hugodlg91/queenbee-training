# Infrastructure cible : zones et matrice des flux

Principe : **une zone par niveau de confiance**, des flux explicitement autorisés entre zones,
**tout le reste refusé**. Les choix structurants sont dans `docs/adr/0009-zones-et-refus-par-defaut.md`
(zones), `0010` (journaux) et `0011` (sauvegarde).

## 1. Les zones

```
 Z1 Hôtes surveillés         Z7 Postes analystes SOC
 (agents, non fiables)       (VPN/ZTNA + MFA)
        │ F1                       │ F8
        ▼                          ▼
 ┌──────────────── Z2 DMZ d'ingestion ─────────────────┐        Internet
 │ proxy inverse : TLS 1.3, limite de débit, ≤ 4 Kio   │        (flux de menaces)
 └──────────────────────┬──────────────────────────────┘              ▲
                        │ F2 (mTLS)                                    │ F7 (sortant, via proxy de sortie)
 ┌──────────────── Z3 Application ─────────────────────┐──────────────┘
 │ cœur Queen Bee (hexagone) · service d'enrichissement│── F6 (mTLS) ──▶ API pare-feu (Z6)
 └───┬──────────────────────┬──────────────────────────┘
     │ F3                   │ F4, F5 (envoi seul)
     ▼                      ▼
 Z4 Données            Z5 Sécurité : collecteur de journaux (immuable), SIEM, sauvegardes
 (base incidents) ──F11──▶ (écriture seule, copies immuables)

 Z6 Administration : bastion MFA, coffre de secrets, API du pare-feu ── F9, F10 vers Z3/Z4
```

| Zone | Contient | Niveau de confiance | Pourquoi une zone à part |
|---|---|---|---|
| **Z1** Hôtes surveillés | serveurs supervisés, agents | non fiable | ce qu'ils envoient peut avoir été écrit par l'attaquant (TB1) |
| **Z2** DMZ d'ingestion | proxy inverse TLS | faible | seule zone joignable depuis Z1 et Z7 ; absorbe et filtre avant le cœur |
| **Z3** Application | cœur Queen Bee, service d'enrichissement | élevé | détient la logique et la clé HMAC ; jamais joignable directement de l'extérieur |
| **Z4** Données | base des incidents | élevé | preuves et données personnelles (IP, comptes) : accès par l'application seule (TB2) |
| **Z5** Sécurité | collecteur de journaux, SIEM, sauvegardes | élevé, **hors de portée de l'application** | si l'application est compromise, elle ne peut ni effacer ses traces ni ses sauvegardes |
| **Z6** Administration | bastion MFA, coffre de secrets, API du pare-feu | maximal | les actions les plus puissantes : isolées, nominatives, tracées |
| **Z7** Postes analystes | postes SOC | moyen | utilisateurs humains authentifiés (MFA), au travers de la DMZ (TB4) |

## 2. Matrice des flux

| Flux | Source → Destination | Protocole / port | Justifié par (élément d'architecture) | STRIDE |
|---|---|---|---|---|
| **F1** | Agents (Z1) → proxy inverse (Z2) | HTTPS 443, TLS 1.3 | port d'entrée des messages d'agent : `agent_api.parse_agent_message` (HMAC, ≤ 4 Kio, schéma strict) | S, T, D |
| **F2** | Proxy inverse (Z2) → cœur Queen Bee (Z3) | HTTPS 8443, **mTLS** | seul le proxy parle au cœur ; certificat client du proxy | S, T |
| **F3** | Cœur (Z3) → base incidents (Z4) | TCP 5432, TLS (au pilote : fichier SQLite local) | port `IncidentRepository` → `SqliteIncidentRepository` (SQL paramétré) | T, I |
| **F4** | Cœur (Z3) → collecteur de journaux (Z5) | syslog TLS 6514, **envoi seul** | journal d'audit `queenbee.audit` (`AuditedNotifier`, `IncidentService`, `CommandHistory`) | R |
| **F5** | Cœur (Z3) → SIEM / SOC (Z5) | syslog TLS 6514 | port `Notifier` derrière `RateLimitedNotifier` (au plus N alertes par fenêtre) | D, I |
| **F6** | Cœur (Z3) → API du pare-feu (Z6) | HTTPS 443, mTLS | port `Firewall` ← `BlockIpCommand` (IP validée à la construction) | E, T |
| **F7** | Cœur (Z3) → fournisseur de menaces (Internet) | HTTPS 443, **sortant uniquement**, via proxy de sortie | `ThreatFeedTranslator` (couche anti-corruption, TB6) | S, T |
| **F8** | Postes analystes (Z7) → proxy inverse (Z2) | HTTPS 443 + MFA, via VPN/ZTNA | cas d'usage `IncidentService.move`, lecture via `IncidentReadProxy` | S, E, I |
| **F9** | Bastion (Z6) → serveurs Z3 / Z4 | SSH 22, depuis le bastion **uniquement**, MFA, comptes nominatifs | administration : déploiement, injection de la configuration (`config.py`) | E, R |
| **F10** | Coffre de secrets (Z6) → cœur (Z3) | HTTPS 8200, mTLS, lecture seule au démarrage | `SettingsBuilder` / `settings_from_env`, `service_key` (une clé par service) | I, S |
| **F11** | Base (Z4) → stockage de sauvegarde (Z5) | TLS, **écriture seule**, copies immuables | sauvegarde 3-2-1, RPO 15 min (`docs/exploitation_securite.md`) | T, D |
| **F12** | Cœur (Z3) → service d'enrichissement (Z3) | HTTPS, mTLS + signature HMAC | `call_enrichment_service` (ADR 0007, faille 6) | S |
| — | **tout le reste** | — | **refusé** (refus par défaut, journalisé) | — |

Exemples de flux **refusés** : Z1 → Z3 directement ; Z3 → Internet hors F7 ; Z5 → Z3 (le SIEM ne parle
jamais à l'application) ; Z3 → effacement dans Z5 ; Z7 → Z4.

## 3. Contrôle de complétude

| Composant | Flux entrants | Flux sortants |
|---|---|---|
| Agents (Z1) | — | F1 |
| Proxy inverse (Z2) | F1, F8 | F2 |
| Cœur Queen Bee (Z3) | F2, F9, F10 | F3, F4, F5, F6, F7, F12 |
| Service d'enrichissement (Z3) | F12, F9 | — |
| Base incidents (Z4) | F3, F9 | F11 |
| Collecteur / SIEM (Z5) | F4, F5 | — |
| Sauvegardes (Z5) | F11 | — |
| Bastion (Z6) | (accès admin MFA) | F9 |
| Coffre de secrets (Z6) | — | F10 |
| API pare-feu (Z6) | F6 | — |
| Postes analystes (Z7) | — | F8 |
| Fournisseur de menaces | F7 (réponse) | — |

**Aucun flux sans élément d'architecture, aucun composant sans flux.**
