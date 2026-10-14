from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from queenbee.domain.model import SecurityEvent

T0 = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)


def ev(ip: str = "10.0.0.66", action: str = "login_failed", user: str = "root") -> SecurityEvent:
    # Import tardif : tant que le domaine n'existe pas, seuls les tests qui en ont besoin échouent.
    from queenbee.domain.model import SecurityEvent  # noqa: PLC0415

    return SecurityEvent(source_ip=ip, username=user, action=action, timestamp=T0)


@pytest.fixture
def five_failures() -> list[SecurityEvent]:
    return [ev() for _ in range(5)]
