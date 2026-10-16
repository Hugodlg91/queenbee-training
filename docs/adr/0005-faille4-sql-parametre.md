# ADR 0005 — Faille 4 : requêtes SQL paramétrées uniquement

- **Statut** : accepté — 16/10/2026 · **Couche** : persistance · **STRIDE** : T, I, E · **DICP** : C, I
- **Contexte** : `f"SELECT * FROM incident WHERE ip = '{ip}'"` mélange code SQL et donnée : `x' OR '1'='1`
  renvoie toute la table, `'; DROP TABLE …` peut la détruire.
- **Décision** : toute requête utilise des paramètres `?` (`execute(sql, (valeur,))`) ; dans `src/`, le SQL
  n'existe que dans `SqliteIncidentRepository` (adaptateur), et ruff `S608` + bandit `B608` bloquent tout f-string SQL.
- **Conséquences** : + une donnée ne devient jamais du code SQL ; − les requêtes dynamiques (filtres variables)
  doivent être construites avec des fragments fixes, jamais à partir de texte reçu.
- **Preuve** : `tests/test_lab_vulnerable.py::test_faille4_sql_injection_returns_nothing`,
  `tests/test_services.py::test_sqlite_repo_resists_injection`
