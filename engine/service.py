from engine.correlation import CorrelationEngine, related_ids
from engine.graph import build_graph
from engine.storage.base import ConflictError, NotFoundError, Repository
from schemas.results import AnalysisRequest, AnalysisResult, Timeline


class AnalysisService:
    def __init__(self, repository: Repository):
        self.repository = repository
        self.engine = CorrelationEngine()

    @staticmethod
    def check_root(events, root: str | None):
        if root and root not in {event.event_id for event in events}:
            raise NotFoundError(f"Root event not found: {root}")

    def analyze(self, case_id: str, request: AnalysisRequest) -> AnalysisResult:
        case = self.repository.get_case(case_id)
        events = self.repository.events(case_id)
        self.check_root(events, request.root_event_id)
        correlations = self.engine.correlate(events, request.min_score)
        self.repository.save_correlations(case_id, correlations, case.revision)
        if request.root_event_id:
            ids = related_ids(correlations, request.root_event_id)
            correlations = [
                edge for edge in correlations if edge.source_event in ids and edge.target_event in ids
            ]
        return AnalysisResult(
            status="completed" if correlations else "no_matches",
            event_count=len(events),
            correlation_count=len(correlations),
            correlations=correlations,
            root_event_id=request.root_event_id,
        )

    def view(self, case_id: str, root: str | None = None):
        before = self.repository.get_case(case_id)
        events = self.repository.events(case_id)
        self.check_root(events, root)
        correlations = self.repository.correlations(case_id)
        after = self.repository.get_case(case_id)
        if before.revision != after.revision:
            raise ConflictError("Evidence changed while reading; reload the case")
        if root:
            ids = related_ids(correlations, root)
            events = [event for event in events if event.event_id in ids]
            correlations = [
                edge for edge in correlations if edge.source_event in ids and edge.target_event in ids
            ]
        return events, correlations

    def graph(self, case_id: str, root: str | None = None):
        revision = self.repository.get_case(case_id).revision
        events, correlations = self.view(case_id, root)
        graph = build_graph(events, correlations, root)
        if root is None and hasattr(self.repository, "save_graph"):
            self.repository.save_graph(case_id, graph, revision)
        return graph

    def timeline(self, case_id: str, root: str | None = None):
        if root:
            events, _ = self.view(case_id, root)
        else:
            events = self.repository.events(case_id)
        return Timeline(events=events, root_event_id=root)
