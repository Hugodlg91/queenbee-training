# Comparaison de deux architectures pour Queen Bee

Deux options réalistes pour le même besoin : recevoir les événements des agents, détecter, ouvrir
des incidents, prévenir le SOC, laisser les analystes trier et bloquer.

- **A. Monolithe modulaire hexagonal** (retenu) : un seul processus Python ; le domaine au centre,
  les ports en `Protocol`, des adaptateurs pour l'API agents, SQLite et les notifications.
- **B. Microservices** : un service d'ingestion, un service de détection, un service incidents,
  reliés par une file de messages (ex. RabbitMQ), chacun avec sa base et son déploiement.

## Critères demandés

| Critère | A. Monolithe hexagonal | B. Microservices |
|---|---|---|
| **Maintenabilité** | un dépôt, un test lance tout en < 2 s ; le découpage en couches est vérifié par `lint-imports` ; refactoring sûr (mypy strict sur tout le code) | chaque service se comprend seul, mais un changement de format d'événement touche 3 services et leurs contrats ; tests de bout en bout lourds (conteneurs, file de messages) |
| **Frontières réseau** | une seule entrée réseau exposée (API agents, TB1) ; les appels internes sont des appels de fonction, sans surface réseau | chaque service expose un port, plus la file de messages : 3 à 4 surfaces à authentifier (mTLS entre services), à filtrer et à superviser |
| **Secrets** | une clé HMAC agents + l'accès base, lus dans `.env` au démarrage (`config.py`, `repr=False`) | des secrets par service : clés HMAC, identifiants de la file, certificats mTLS, accès à chaque base ; il faut un coffre (Vault) et leur rotation |
| **Failles typiques** | contournement d'une couche si quelqu'un importe `sqlite3` dans le domaine (bloqué par `lint-imports`) ; un bug dans un adaptateur tourne avec les droits de tout le processus | service interne laissé sans authentification (« il n'est pas exposé ») ; messages de la file non signés (un service compromis injecte de faux événements) ; dérive des versions de contrat entre services |
| **Disponibilité** | un plantage arrête tout ; on y répond par la validation à l'entrée et l'isolation des abonnés (`AlertBus`) | un service peut tomber sans arrêter les autres ; mais les pannes partielles sont plus difficiles à diagnostiquer |

## Un choix proportionné

| Contrainte | Situation de Queen Bee | Conséquence |
|---|---|---|
| **Volume** | quelques dizaines d'agents, quelques milliers d'événements par minute : un processus Python suffit largement | le passage à l'échelle des microservices n'apporte rien aujourd'hui |
| **Équipe** | 4 personnes, sans équipe d'exploitation | impossible d'opérer correctement mTLS, coffre-fort de secrets, file de messages et supervision de plusieurs services |
| **Délai** | 3 jours | le monolithe hexagonal est livrable et testé dans le délai ; les microservices ne le sont pas |

**Décision** : A, le monolithe modulaire hexagonal (voir `docs/adr/0001-architecture-hexagonale.md`).
Les ports rendent une migration possible plus tard : l'adaptateur `agent_api` pourrait devenir un
service séparé sans toucher au domaine, si le volume l'impose un jour.
