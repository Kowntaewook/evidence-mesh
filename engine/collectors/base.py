from pathlib import Path
from typing import Protocol

from engine.normalization import normalize_events
from engine.parsers.base import Parser
from schemas.events import Event, Source


class Collector(Protocol):
    def collect(self, path: Path, parser: Parser) -> list[Event]: ...


class ArtifactCollector:
    """Import an existing artifact; never acquire live or modify original evidence."""

    def __init__(self, source: Source):
        self.source = source

    def collect(self, path: Path, parser: Parser) -> list[Event]:
        events = normalize_events(list(parser.parse(path)))
        if any(event.source != self.source for event in events):
            raise ValueError(f"Expected only {self.source} events in {path.name}")
        return events
