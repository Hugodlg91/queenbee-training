"""Configuration : Builder -> Settings figé et validé ; secrets lus dans l'environnement."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Self

MIN_KEY_BYTES: Final = 32
MAX_THRESHOLD: Final = 10_000
_THRESHOLD: Final = re.compile(r"[0-9]{1,5}")  # ni signe, ni "1_000", ni "True"


class ConfigError(ValueError):
    """Configuration absente ou invalide : l'application refuse de démarrer."""


@dataclass(frozen=True, slots=True)
class Settings:
    """Figé, et le secret n'apparaît ni dans repr(), ni dans str(), ni dans les logs."""

    hmac_key: bytes = field(repr=False)
    db_path: str = ":memory:"  # la prod fixe QUEENBEE_DB ; les tests ne créent aucun fichier
    bf_threshold: int = 5

    def __post_init__(self) -> None:
        if not isinstance(self.hmac_key, bytes) or len(self.hmac_key) < MIN_KEY_BYTES:
            raise ConfigError(f"clé HMAC absente ou trop courte (>= {MIN_KEY_BYTES} octets)")
        if not isinstance(self.db_path, str) or not self.db_path or "\x00" in self.db_path:
            raise ConfigError("chemin de base invalide")
        threshold = self.bf_threshold
        if isinstance(threshold, bool) or not isinstance(threshold, int):
            raise ConfigError("seuil entier attendu")
        if not 1 <= threshold <= MAX_THRESHOLD:
            raise ConfigError(f"seuil hors de [1, {MAX_THRESHOLD}]")


class SettingsBuilder:
    """Assemble pas à pas ; tout est validé une seule fois, à la fin, dans build()."""

    def __init__(self) -> None:
        self._hmac_key: bytes | None = None
        self._db_path = ":memory:"
        self._bf_threshold = 5

    def hmac_key(self, key: bytes) -> Self:
        self._hmac_key = key
        return self

    def db_path(self, path: str) -> Self:
        self._db_path = path
        return self

    def bf_threshold(self, threshold: int) -> Self:
        self._bf_threshold = threshold
        return self

    def build(self) -> Settings:
        if self._hmac_key is None:
            raise ConfigError("clé HMAC manquante")
        return Settings(self._hmac_key, self._db_path, self._bf_threshold)


def settings_from_env(env: Mapping[str, str] | None = None) -> Settings:
    """Lit QUEENBEE_AGENT_KEY (hex), QUEENBEE_DB et QUEENBEE_BF_THRESHOLD."""
    env = os.environ if env is None else env
    builder = SettingsBuilder()
    try:
        builder.hmac_key(bytes.fromhex(env.get("QUEENBEE_AGENT_KEY", "")))
    except ValueError:
        # from None : l'exception d'origine contiendrait un extrait de la valeur secrète.
        raise ConfigError("QUEENBEE_AGENT_KEY doit être en hexadécimal") from None
    if "QUEENBEE_DB" in env:
        builder.db_path(env["QUEENBEE_DB"])
    if "QUEENBEE_BF_THRESHOLD" in env:
        raw = env["QUEENBEE_BF_THRESHOLD"].strip()
        if not _THRESHOLD.fullmatch(raw):
            raise ConfigError("QUEENBEE_BF_THRESHOLD doit être un entier positif")
        builder.bf_threshold(int(raw))
    return builder.build()
