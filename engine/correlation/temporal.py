from engine.correlation.base import reason
from schemas.events import Event
from schemas.results import Reason


class TemporalRule:
    def evaluate(self, left: Event, right: Event) -> list[Reason]:
        if "extraction_time" in {left.timestamp_semantics, right.timestamp_semantics}:
            return []
        seconds = abs((left.timestamp - right.timestamp).total_seconds())
        for limit, score in ((2, 30), (5, 25), (30, 15), (60, 5)):
            if seconds <= limit:
                return [reason("temporal_proximity", score, f"{seconds:g} seconds apart", "timestamp")]
        return []
