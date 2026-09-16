from itertools import combinations

from engine.correlation.artifacts import ArtifactRule, negative_reasons
from engine.correlation.base import CorrelationRule
from engine.correlation.file import FileRule
from engine.correlation.index import EventIndex
from engine.correlation.network import NetworkRule
from engine.correlation.process import ProcessRule
from engine.correlation.temporal import TemporalRule
from schemas.events import Event
from schemas.results import Correlation

# Weak metadata or temporal coincidence cannot create an edge by themselves.
ANCHORS = {
    "same_process_instance",
    "parent_process_instance",
    "same_process_id",
    "parent_process",
    "same_file_path",
    "same_sha256",
    "command_line_file_path",
    "command_line_filename",
    "prefetch_reference",
    "same_socket_tuple",
    "same_destination_endpoint",
    "dns_resolved_destination",
    "same_dns_query",
    "same_mft_reference",
    "same_file_object",
    "prefetch_executable_path",
    "prefetch_executable_name",
    "amcache_executable_path",
    "tls_sni_domain",
}


class CorrelationEngine:
    def __init__(self, rules: list[CorrelationRule] | None = None):
        self.indexed = rules is None
        self.stats = {}
        self.rules = (
            rules
            if rules is not None
            else [TemporalRule(), ProcessRule(), FileRule(), NetworkRule(), ArtifactRule()]
        )

    def correlate(self, events: list[Event], min_score: int = 50) -> list[Correlation]:
        if not events:
            raise ValueError("Cannot analyze an empty case")
        if not 1 <= min_score <= 100:
            raise ValueError("min_score must be between 1 and 100")
        if not all(isinstance(e, Event) for e in events):
            raise TypeError("Correlation requires normalized Event objects")
        if len({e.event_id for e in events}) != len(events):
            raise ValueError("Duplicate event IDs")
        results = []
        ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
        if self.indexed:
            index = EventIndex(ordered)
            pairs = index.pairs()
            self.stats = {
                "events": len(events),
                "candidate_pairs": len(pairs),
                "all_pairs": len(events) * (len(events) - 1) // 2,
                "indexes": index.sizes(),
            }
        else:
            pairs = combinations(range(len(ordered)), 2)
            self.stats = {"custom_rules": True}
        for i, j in pairs:
            left, right = ordered[i], ordered[j]
            if left.hostname and right.hostname and left.hostname != right.hostname:
                continue
            # Do not stitch distinct process lifetimes through coincidental metadata.
            a, b = left.process, right.process
            if (
                a
                and b
                and a.pid == b.pid
                and a.creation_time
                and b.creation_time
                and a.creation_time != b.creation_time
            ):
                continue
            reasons = [reason for rule in self.rules for reason in rule.evaluate(left, right)]
            if not any(reason.rule in ANCHORS for reason in reasons):
                continue
            if self.indexed:
                negatives = negative_reasons(left, right)
                if any(reason.rule == "process_lifetime_conflict" for reason in negatives):
                    continue
                if any(reason.rule == "temporal_distance" for reason in negatives) and not any(
                    reason.rule
                    in {
                        "same_sha256",
                        "same_process_instance",
                        "parent_process_instance",
                        "same_process_creation",
                        "same_mft_reference",
                        "same_file_object",
                    }
                    for reason in reasons
                ):
                    continue
                # Source corroboration requires a typed artifact and a substantive identity signal.
                if left.source != right.source and (left.artifact_type or right.artifact_type):
                    strong = [r for r in reasons if r.rule in ANCHORS and r.score >= 35]
                    if strong:
                        from engine.correlation.base import reason

                        reasons.append(
                            reason(
                                "cross_source_corroboration",
                                10,
                                f"Independent {left.source} and {right.source} observations",
                                "source",
                                "provenance",
                            )
                        )
                reasons.extend(negatives)
            score = max(0, min(100, sum(reason.score for reason in reasons)))
            if score >= min_score:
                results.append(
                    Correlation(
                        source_event=left.event_id, target_event=right.event_id, score=score, reasons=reasons
                    )
                )
        return results


def related_ids(correlations: list[Correlation], root_event_id: str) -> set[str]:
    """All reachable evidence, preserving the individual (non-transitive) edge scores."""
    adjacent: dict[str, set[str]] = {}
    for edge in correlations:
        adjacent.setdefault(edge.source_event, set()).add(edge.target_event)
        adjacent.setdefault(edge.target_event, set()).add(edge.source_event)
    seen, todo = {root_event_id}, [root_event_id]
    while todo:
        for candidate in adjacent.get(todo.pop(), set()) - seen:
            seen.add(candidate)
            todo.append(candidate)
    return seen
