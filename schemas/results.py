from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import Field, model_validator

from engine.version import VERSION
from schemas.events import Event, Model, Provenance, Timestamp


class Reason(Model):
    rule: str
    score: Annotated[int, Field(ge=-100, le=100)]
    details: str
    evidence: list[str] = Field(default_factory=list)


class Correlation(Model):
    source_event: str
    target_event: str
    score: Annotated[int, Field(ge=0, le=100)]
    reasons: list[Reason] = Field(min_length=1)
    raw_score: int | None = None
    rule_version: str = VERSION

    @model_validator(mode="after")
    def score_matches_reasons(self):
        if self.source_event == self.target_event:
            raise ValueError("A correlation requires two distinct events")
        raw = sum(reason.score for reason in self.reasons)
        if self.raw_score is not None and self.raw_score != raw:
            raise ValueError("raw_score must equal sum(reasons.score)")
        object.__setattr__(self, "raw_score", raw)
        if self.score != max(0, min(100, raw)):
            raise ValueError("score must equal clamp(sum(reasons.score), 0, 100)")
        return self


class NodeKind(StrEnum):
    PROCESS = "Process"
    FILE = "File"
    IP = "IP"
    DOMAIN = "Domain"
    USER = "User"
    REGISTRY = "Registry"
    EVENT = "Event"
    MFT_RECORD = "MFTRecord"
    SOCKET = "Socket"
    FLOW = "NetworkFlow"
    SERVICE = "Service"
    REGISTRY_ARTIFACT = "RegistryArtifact"
    DLL = "DLL"
    MODULE = "Module"
    DRIVER = "Driver"
    MEMORY_REGION = "MemoryRegion"
    FILE_OBJECT = "FileObject"


class EdgeKind(StrEnum):
    LOADED = "LOADED"
    STARTED = "STARTED"
    CREATED = "CREATED"
    ACCESSED = "ACCESSED"
    CONNECTED_TO = "CONNECTED_TO"
    RESOLVED = "RESOLVED"
    DOWNLOADED = "DOWNLOADED"
    EXECUTED = "EXECUTED"
    PARENT_OF = "PARENT_OF"
    CORRELATED_WITH = "CORRELATED_WITH"
    OBSERVED = "OBSERVED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    OPENED = "OPENED"
    RESOLVED_TO = "RESOLVED_TO"
    REFERENCES = "REFERENCES"
    USES_BINARY = "USES_BINARY"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    EXTRACTED_FROM = "EXTRACTED_FROM"


class Node(Model):
    id: str
    kind: NodeKind
    label: str
    event_ids: list[str]


class Edge(Model):
    id: str
    source: str
    target: str
    kind: EdgeKind
    event_ids: list[str]
    score: int | None = None
    reasons: list[Reason] = Field(default_factory=list)
    timestamp: Timestamp | None = None
    provenance: list[Provenance] = Field(default_factory=list)
    support_count: int = 1


class IncidentGraph(Model):
    nodes: list[Node]
    edges: list[Edge]
    root_event_id: str | None = None
    truncated: bool = False
    supporting_events: list[Event] = Field(default_factory=list)


class CaseCreate(Model):
    name: str = Field(min_length=1, max_length=200, pattern=r"\S")
    description: str = Field(default="", max_length=5000)


class Case(CaseCreate):
    case_id: str
    created_at: Timestamp = Field(default_factory=lambda: datetime.now(UTC))
    event_count: int = 0
    revision: int = 0
    analysis_revision: int | None = None


class AnalysisRequest(Model):
    root_event_id: str | None = None
    min_score: int = Field(default=50, ge=1, le=100)
    result_limit: int | None = Field(default=None, ge=1, le=5000)


class AnalysisResult(Model):
    status: str
    event_count: int
    correlation_count: int
    correlations: list[Correlation]
    root_event_id: str | None = None
    truncated: bool = False


class Timeline(Model):
    events: list[Event]
    root_event_id: str | None = None
