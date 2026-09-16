from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import Field

from schemas.events import Event, Identifier, Model, Source, SourceArtifact, Timestamp


class RunStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    SKIPPED = "SKIPPED"


class ArtifactContext(Model):
    acquisition_id: Identifier
    extracted_at: Timestamp
    hostname: str | None = None
    tool_version: str | None = None
    volume_id: str | None = None
    timezone: str | None = None
    recovered_directory: str | None = None
    mount_point: str | None = None
    logical_path: str | None = None


class ParserRun(Model):
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    import_id: str | None = None
    parser: str
    plugin: str | None = None
    source: Source
    status: RunStatus
    started_at: Timestamp = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: Timestamp | None = None
    event_count: int = 0
    row_count: int = 0
    error: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    command: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    artifact: SourceArtifact | None = None


class ImportBatch(Model):
    events: list[Event] = Field(default_factory=list)
    runs: list[ParserRun] = Field(default_factory=list)


class ImportRequest(Model):
    path: str
    format: str | None = None
    context: ArtifactContext
    plugins: list[str] | None = None


class ImportReport(Model):
    import_id: str
    case_id: str
    imported: int
    status: str
    runs: list[ParserRun]
