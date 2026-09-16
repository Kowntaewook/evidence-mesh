from typing import Protocol

from schemas.events import Event
from schemas.results import Reason


class CorrelationRule(Protocol):
    """Pure, symmetric rule operating exclusively on normalized Events."""

    def evaluate(self, left: Event, right: Event) -> list[Reason]: ...


def same_host(left: Event, right: Event) -> bool:
    return bool(left.hostname and right.hostname and left.hostname == right.hostname)


def reason(rule: str, score: int, details: str, *fields: str) -> Reason:
    return Reason(rule=rule, score=score, details=details, evidence=list(fields))
