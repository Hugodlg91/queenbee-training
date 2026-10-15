"""Réponse à incident : Command (blocage d'IP validé, tracé, annulable) devant le port Firewall."""

from __future__ import annotations

import ipaddress
import logging
from typing import Protocol

from queenbee.application.ports import Firewall
from queenbee.domain.model import DomainError

_audit_log = logging.getLogger("queenbee.audit")


class InMemoryFirewall:
    """Pare-feu de test : une simple liste de blocage."""

    def __init__(self) -> None:
        self.blocked: set[str] = set()

    def block(self, ip: str) -> None:
        self.blocked.add(ip)

    def unblock(self, ip: str) -> None:
        self.blocked.discard(ip)


class Command(Protocol):
    def execute(self) -> None: ...

    def undo(self) -> None: ...


class BlockIpCommand:
    """La cible est validée DANS LE CONSTRUCTEUR : une commande invalide n'existe jamais.

    `10.0.0.1; iptables -F` n'est pas une IP : impossible de l'envoyer au pare-feu.
    """

    def __init__(self, firewall: Firewall, ip: str) -> None:
        address = ipaddress.ip_address(ip)  # ValueError « does not appear to be an IP address »
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            raise DomainError("bloquer cette adresse couperait le service lui-même")
        self._firewall = firewall
        self.ip = str(address)

    def execute(self) -> None:
        self._firewall.block(self.ip)

    def undo(self) -> None:
        self._firewall.unblock(self.ip)

    def __repr__(self) -> str:
        return f"BlockIpCommand({self.ip})"


class CommandHistory:
    """Exécute, journalise et permet d'annuler la dernière action (Preuve, Intégrité)."""

    def __init__(self) -> None:
        self._done: list[Command] = []

    def run(self, command: Command) -> None:
        command.execute()
        self._done.append(command)
        _audit_log.info("commande exécutée : %r", command)

    def undo_last(self) -> None:
        if not self._done:
            raise DomainError("aucune commande à annuler")
        command = self._done.pop()
        command.undo()
        _audit_log.info("commande annulée : %r", command)
