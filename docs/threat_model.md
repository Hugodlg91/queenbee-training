# Modèle de menaces — Queen Bee (gabarit à compléter)

## 1. Actifs
| Actif | Pourquoi il compte | C / I / D |
|---|---|---|
| Incidents | preuve + pilotage de la réponse | C, I |
| Clé HMAC agents | permet d'injecter de faux événements | C |
| Règles de détection | un attaquant qui les modifie devient invisible | I |

## 2. Acteurs
Agent (machine), Analyste SOC, Admin, Attaquant externe, Agent compromis.

## 3. Frontières de confiance
TB1 Réseau agents -> API ingestion · TB2 Application -> base · TB3 Application -> pare-feu · TB4 Analyste -> UI

## 4. STRIDE par flux
| Flux | S | T | R | I | D | E | Exigence |
|---|---|---|---|---|---|---|---|
| Agent -> Ingestion | faux agent | message altéré | | | flood | | EX-01 HMAC, EX-02 taille max, EX-03 rate limit |

## 5. Exigences de sécurité (EX-nn, testables)
- EX-01 Tout message d'agent est authentifié (HMAC-SHA256, comparaison temps constant). Test : `test_abuse_forged_signature_rejected`.
