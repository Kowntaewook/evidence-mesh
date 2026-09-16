from pathlib import Path

from engine.collectors import ArtifactCollector
from engine.parsers.json_events import JsonEventParser
from schemas.events import Event, Source

DEFAULT_SAMPLE_DIR = Path(__file__).resolve().parent.parent / "samples" / "sample_case"


def load_sample(path: Path = DEFAULT_SAMPLE_DIR) -> list[Event]:
    events = []
    for source in Source:
        events.extend(
            ArtifactCollector(source).collect(path / f"{source.value}_events.json", JsonEventParser())
        )
    if len({event.event_id for event in events}) != len(events):
        raise ValueError("Duplicate IDs across sample sources")
    return events
