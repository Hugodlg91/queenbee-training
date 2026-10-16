# ADR 0003 — Faille 2 : regex bornée et sans répétition imbriquée (ReDoS)

- **Statut** : accepté — 16/10/2026 · **Couche** : adaptateur d'entrée · **STRIDE** : D · **DICP** : D
- **Contexte** : `^([a-zA-Z0-9]+\s?)*$` imbrique deux répétitions : sur `"aaaa…a!"`, le moteur essaie toutes
  les façons de découper la chaîne ; +4 caractères multiplient le temps par 16. Une seule ligne bloque le service.
- **Décision** : longueur bornée (≤ 64) **avant** la regex, motif `[a-zA-Z0-9]+(?: [a-zA-Z0-9]+)*` en
  `fullmatch` (une seule façon de découper, temps linéaire). Même règle dans `src/` : `parse_sshd_line` borne à 512.
- **Conséquences** : + temps constant quelle que soit l'entrée ; − les noms à espaces multiples ou de plus de
  64 caractères sont refusés (acceptable pour des identifiants).
- **Preuve** : `tests/test_lab_vulnerable.py::test_faille2_redos_fixed_time_is_bounded`,
  `tests/test_adapters.py::test_parser_is_fast_on_adversarial_input`
