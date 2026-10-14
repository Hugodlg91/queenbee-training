"""Notifiers : implémentations du port Notifier."""

from __future__ import annotations

import logging

from queenbee.domain.model import Alert

_alerts_log = logging.getLogger("queenbee.alerts")


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
