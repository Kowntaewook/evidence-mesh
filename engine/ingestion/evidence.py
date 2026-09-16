"""Read-only artifact utilities shared by independent format adapters."""

import csv
import hashlib
import io
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from engine.normalization import normalize_event
from engine.version import VERSION
from schemas.events import Event, ParserInfo, Provenance, RawReference, Source, SourceArtifact
from schemas.imports import ArtifactContext


class ArtifactError(ValueError):
    pass


class DependencyUnavailable(ArtifactError):
    pass


def digest_file(path: Path) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def key(value: str) -> str:
    return re.sub(r"[\s_()-]", "", value).casefold()


def pick(row: dict, *names: str, required: bool = False):
    found = [value for label, value in row.items() if key(label) in {key(name) for name in names}]
    present = [value for value in found if value not in (None, "", "-", "N/A")]
    if len(present) > 1 and any(value != present[0] for value in present):
        raise ArtifactError(f"Conflicting columns: {', '.join(names)}")
    if not present:
        if required:
            raise ArtifactError(f"Missing required field: {names[0]}")
        return None
    return present[0]


def number(value, field: str, required: bool = False, maximum: int | None = None) -> int | None:
    if value in (None, "", "-", "N/A"):
        if required:
            raise ArtifactError(f"Missing required field: {field}")
        return None
    if isinstance(value, bool) or isinstance(value, float):
        raise ArtifactError(f"{field} must be an integer")
    try:
        result = int(value, 16 if value.lower().startswith("0x") else 10) if isinstance(value, str) else value
    except ValueError as exc:
        raise ArtifactError(f"Invalid {field}: {value!r}") from exc
    if not isinstance(result, int) or result < 0 or (maximum is not None and result > maximum):
        raise ArtifactError(f"Invalid {field}: {value!r}")
    return result


def boolean(value, field: str) -> bool | None:
    if value in (None, "", "-", "N/A"):
        return None
    if value in (True, 1, "1", "True", "true", "Yes", "yes"):
        return True
    if value in (False, 0, "0", "False", "false", "No", "no"):
        return False
    raise ArtifactError(f"Invalid {field}: expected boolean")


def address(value, field: str, required: bool = False) -> str | None:
    parsed = number(value, field, required)
    return hex(parsed) if parsed is not None else None


def text_value(value, field: str, required: bool = False) -> str | None:
    if value in (None, "", "-", "N/A"):
        if required:
            raise ArtifactError(f"Missing required field: {field}")
        return None
    if not isinstance(value, str):
        raise ArtifactError(f"{field} must be text")
    return value


def parse_time(value, context: ArtifactContext, field: str = "timestamp") -> datetime | None:
    if value in (None, "", "-", "N/A", "0001-01-01T00:00:00", "1601-01-01 00:00:00"):
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        value = re.sub(r"\s+UTC(?:\+0000)?$", "+00:00", value)
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ArtifactError(f"Invalid {field}: {value!r}") from exc
    else:
        raise ArtifactError(f"{field} must be an ISO timestamp")
    if parsed.tzinfo is None:
        if not context.timezone:
            raise ArtifactError(f"{field} has no timezone; supply explicit source timezone")
        zone = ZoneInfo(context.timezone)
        if parsed.replace(tzinfo=zone, fold=0).utcoffset() != parsed.replace(tzinfo=zone, fold=1).utcoffset():
            raise ArtifactError(f"{field} is ambiguous in {context.timezone}; supply an explicit offset")
        parsed = parsed.replace(tzinfo=zone)
    return parsed.astimezone(UTC)


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ArtifactError(f"Duplicate JSON key: {name}")
        result[name] = value
    return result


def json_loads(content: str):
    def invalid(value):
        raise ArtifactError(f"Invalid JSON constant: {value}")

    return json.loads(content, object_pairs_hook=unique_object, parse_constant=invalid)


class EvidenceReader:
    def __init__(self, path: Path, source: Source, kind: str, context: ArtifactContext, parser: str):
        self.path, self.source, self.kind, self.context = Path(path), source, kind, context
        digest, size = digest_file(self.path)
        self.artifact = SourceArtifact(
            artifact_id=f"sha256:{digest}",
            kind=kind,
            path=str(self.path.resolve()),
            sha256=digest,
            size=size,
            imported_at=datetime.now(UTC),
        )
        self.parser = ParserInfo(name=parser, version=VERSION)

    def rows(self) -> list[tuple[str, dict]]:
        try:
            payload = self.path.read_text(encoding="utf-8-sig")
            if self.path.suffix.casefold() == ".json":
                rows = json_loads(payload)
                if not isinstance(rows, list) or not rows or not all(isinstance(row, dict) for row in rows):
                    raise ArtifactError("Expected a nonempty JSON record array")
                return [(f"/{i}", row) for i, row in enumerate(rows)]
            reader = csv.DictReader(io.StringIO(payload, newline=""), strict=True)
            if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
                raise ArtifactError("Missing or duplicate CSV headers")
            rows = []
            for row in reader:
                if None in row or any(value is None for value in row.values()):
                    raise ArtifactError(f"CSV row {reader.line_num} does not match headers")
                rows.append((f"csv:line:{reader.line_num}", row))
            if not rows:
                raise ArtifactError("No records in CSV")
            return rows
        except (UnicodeError, ValueError, csv.Error) as exc:
            raise ArtifactError(f"{self.path}: {exc}") from exc

    def provenance(self, locator: str, row: dict, index: int, plugin: str | None = None) -> Provenance:
        return Provenance(
            source_artifact=self.artifact,
            parser=self.parser,
            source=self.source,
            raw_reference=RawReference(artifact_id=self.artifact.artifact_id, locator=locator),
            tool=self.parser.name,
            tool_version=self.context.tool_version,
            plugin=plugin,
            acquisition_id=self.context.acquisition_id,
            memory_image_id=self.context.acquisition_id if self.source == Source.MEMORY else None,
            extraction_timestamp=self.context.extracted_at,
            row_index=index,
            raw=row,
        )

    def event(
        self, locator: str, row: dict, index: int, event_type: str, observed=None, suffix: str = "", **fields
    ) -> Event:
        provenance = self.provenance(locator, row, index)
        identity = json.dumps(
            [self.context.acquisition_id, self.artifact.sha256, locator, event_type, suffix]
        )
        return normalize_event(
            {
                "event_id": "EM-" + hashlib.sha256(identity.encode()).hexdigest()[:28],
                "timestamp": observed or self.context.extracted_at,
                "timestamp_semantics": "event_time" if observed else "extraction_time",
                "source": self.source,
                "type": event_type,
                "artifact_type": self.kind,
                "hostname": self.context.hostname,
                "source_artifact": self.artifact.model_dump(mode="json"),
                "parser": self.parser.model_dump(),
                "raw_reference": provenance.raw_reference.model_dump(),
                "raw": row,
                "provenance": [provenance.model_dump(mode="json")],
                "metadata": {"acquisition_id": self.context.acquisition_id},
                **fields,
            }
        )
