from typing import Protocol

from schemas.events import Event
from schemas.results import Case, CaseCreate, Correlation


class Repository(Protocol):
    def create_case(self, request: CaseCreate) -> Case: ...
    def list_cases(self) -> list[Case]: ...
    def get_case(self, case_id: str) -> Case: ...
    def add_events(self, case_id: str, events: list[Event]) -> int: ...
    def events(self, case_id: str) -> list[Event]: ...
    def save_correlations(self, case_id: str, correlations: list[Correlation], revision: int) -> None: ...
    def correlations(self, case_id: str) -> list[Correlation]: ...


class NotFoundError(Exception):
    pass


class ConflictError(Exception):
    pass


class AnalysisRequiredError(Exception):
    pass
