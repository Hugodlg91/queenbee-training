"""Adaptateur d'entrée : lignes d'access.log (format CLF ou combined) -> HttpRequest validés."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Final, TextIO

from bonus.http_log_audit.model import AuditError, HttpRequest

MAX_LINE_LENGTH: Final = 8192

# Ancré (fullmatch), chaque champ borné, aucun quantificateur imbriqué : pas de ReDoS.
_ACCESS_LINE: Final = re.compile(
    r"(?P<ip>[0-9A-Fa-f:.]{2,45}) \S{1,64} \S{1,64} \[[^\]]{1,40}\] "
    r'"(?P<method>[A-Z]{1,10}) (?P<target>[^"]{1,2048}) HTTP/[0-9]\.[0-9]" '
    r"(?P<status>[0-9]{3}) (?:[0-9]{1,12}|-)"
    r'(?: "[^"]{0,2048}" "[^"]{0,1024}")?'
)


def parse_access_line(line: str) -> HttpRequest:
    if len(line) > MAX_LINE_LENGTH:
        raise AuditError("ligne trop longue")
    match = _ACCESS_LINE.fullmatch(line.rstrip("\r\n"))
    if match is None:
        raise AuditError("ligne non reconnue")
    return HttpRequest(
        client_ip=match["ip"],
        method=match["method"],
        target=match["target"],
        status=int(match["status"]),  # le statut est lu dans SON champ, pas cherché dans la ligne
    )


@dataclass(frozen=True, slots=True)
class ParseReport:
    requests: tuple[HttpRequest, ...]
    rejected: int


def parse_lines(lines: Iterable[str]) -> ParseReport:
    """Une ligne piégée est rejetée et comptée ; elle n'arrête jamais l'analyse."""
    requests: list[HttpRequest] = []
    rejected = 0
    for line in lines:
        if not line.strip():
            continue
        try:
            requests.append(parse_access_line(line))
        except AuditError:
            rejected += 1
    return ParseReport(tuple(requests), rejected)


def bounded_lines(stream: TextIO, max_length: int = MAX_LINE_LENGTH) -> Iterator[str]:
    """Comme `for line in stream`, sans jamais charger plus de max_length + 1 caractères."""
    while line := stream.readline(max_length + 1):
        if len(line) > max_length and not line.endswith("\n"):
            while (rest := stream.readline(max_length)) and not rest.endswith("\n"):
                pass  # on jette la fin de la ligne géante, morceau par morceau
        yield line
