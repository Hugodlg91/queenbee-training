"""Notifiers : implémentations du port Notifier."""

from __future__ import annotations

import logging
import time
from collections import deque
from collections.abc import Callable

from queenbee.application.ports import Notifier
from queenbee.domain.model import Alert

_alerts_log = logging.getLogger("queenbee.alerts")
_audit_log = logging.getLogger("queenbee.audit")

Clock = Callable[[], float]


class MemoryNotifier:
    """Garde les alertes en mémoire : famille « tests »."""

    def __init__(self) -> None:
        self.received: list[Alert] = []

    def notify(self, alert: Alert) -> None:
        self.received.append(alert)


class LoggingNotifier:
    """Famille « production » : alerte vers le journal (collecté par le SIEM), sans secret SMTP."""

    def notify(self, alert: Alert) -> None:
        _alerts_log.warning(
            "alerte %s sur %s (%s) : %s",
            alert.rule,
            alert.source_ip,
            alert.severity.name,
            alert.detail,
        )


class AuditedNotifier:
    """Décorateur : même interface, et chaque alerte transmise laisse une trace d'audit (Preuve)."""

    def __init__(self, inner: Notifier) -> None:
        self._inner = inner

    def notify(self, alert: Alert) -> None:
        _audit_log.info("alerte %s sur %s transmise", alert.rule, alert.source_ip)
        self._inner.notify(alert)


class RateLimitedNotifier:
    """Décorateur : au plus N alertes par fenêtre glissante ; le surplus est compté (Disponibilité).

    L'horloge est injectée : les tests avancent le temps au lieu d'attendre.
    """

    def __init__(
        self,
        inner: Notifier,
        max_per_window: int = 10,
        window_s: float = 60.0,
        clock: Clock = time.monotonic,
    ) -> None:
        if isinstance(max_per_window, bool) or not isinstance(max_per_window, int):
            raise ValueError("max_per_window entier attendu")
        if max_per_window < 1 or window_s <= 0:
            raise ValueError("limite et fenêtre doivent être positives")
        self._inner = inner
        self._max = max_per_window
        self._window = window_s
        self._clock = clock
        self._sent: deque[float] = deque()
        self.dropped = 0

    def notify(self, alert: Alert) -> None:
        now = self._clock()
        while self._sent and now - self._sent[0] >= self._window:
            self._sent.popleft()
        if len(self._sent) >= self._max:
            self.dropped += 1
            return
        self._sent.append(now)
        self._inner.notify(alert)
