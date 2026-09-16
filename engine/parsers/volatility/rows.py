"""Volatility 3 JSON renderer reader. No Volatility runtime dependency."""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import Field

from engine.version import VERSION
from schemas.events import (
    Event,
    Identifier,
    Model,
    ParserInfo,
    Provenance,
    RawReference,
    SourceArtifact,
    Timestamp,
)

PLUGINS = ("windows.pslist", "windows.pstree", "windows.cmdline", "windows.netscan", "windows.dlllist")
CLASSES = dict(zip(PLUGINS, ("PsList", "PsTree", "CmdLine", "NetScan", "DllList"), strict=True))
ABSENT = {"", "-", "n/a", "not available", "not applicable", "unreadable", "unparsable", "unknown"}


class VolatilityImportError(ValueError):
    """Invalid export or ambiguous merge; imports are all-or-nothing."""


class ImportContext(Model):
    memory_image_id: Identifier
    extraction_timestamp: Timestamp
    hostname: str | None = None
    volatility_version: str | None = None


class ImportResult(Model):
    events: list[Event] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    input_files: int = 0
    input_rows: int = 0


def plugin_name(value: str) -> str:
    for plugin, class_name in CLASSES.items():
        if value.casefold() in {plugin, f"{plugin}.{class_name}".casefold()}:
            return plugin
    raise VolatilityImportError(f"Unsupported Volatility plugin: {value}; supported: {', '.join(PLUGINS)}")


def absent(value: Any) -> bool:
    return value is None or isinstance(value, str) and value.strip().casefold() in ABSENT


def get(row: dict, *names: str) -> Any:
    matches = [row[name] for name in names if name in row and not absent(row[name])]
    if len(matches) > 1 and any(value != matches[0] for value in matches[1:]):
        raise VolatilityImportError(f"Conflicting aliases for {names[0]}")
    return matches[0] if matches else None


def integer(value: Any, field: str, required: bool = False, maximum: int | None = None) -> int | None:
    if absent(value):
        if required:
            raise VolatilityImportError(f"Missing required {field}")
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise VolatilityImportError(f"Invalid {field}: expected integer or hex string")
    try:
        number = int(value, 16 if value.lower().startswith("0x") else 10) if isinstance(value, str) else value
    except ValueError as exc:
        raise VolatilityImportError(f"Invalid {field}: {value!r}") from exc
    if number < 0 or maximum is not None and number > maximum:
        raise VolatilityImportError(f"{field} out of range: {number}")
    return number


def string(value: Any, field: str, required: bool = False) -> str | None:
    if absent(value):
        if required:
            raise VolatilityImportError(f"Missing required {field}")
        return None
    if not isinstance(value, str):
        raise VolatilityImportError(f"Invalid {field}: expected text")
    return value


def timestamp(value: Any, field: str) -> datetime | None:
    if absent(value):
        return None
    if not isinstance(value, str):
        raise VolatilityImportError(f"Invalid {field}: expected timezone-aware timestamp")
    # ISO from JSON renderer, plus the explicit 'UTC' suffix used by older exported tables.
    text = re.sub(r"\s+UTC(?:\+0000)?$", "+00:00", value.strip(), flags=re.IGNORECASE)
    try:
        result = datetime.fromisoformat(text)
    except ValueError as exc:
        raise VolatilityImportError(f"Invalid {field}: {value!r}") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise VolatilityImportError(f"{field} has no timezone; provide an explicit UTC offset")
    return result.astimezone(UTC)


@dataclass
class ExportRow:
    plugin: str
    raw: dict
    provenance: Provenance
    parent_pid: int | None = None

    def error(self, message: str) -> VolatilityImportError:
        return VolatilityImportError(
            f"{self.plugin} {self.provenance.source_artifact.path}"
            f"#{self.provenance.raw_reference.locator}: {message}"
        )


def unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise VolatilityImportError(f"Duplicate JSON key: {key}; refusing to discard an observation")
        result[key] = value
    return result


def read_rows(path: Path, plugin: str, context: ImportContext, *, extended: bool = False) -> list[ExportRow]:
    if extended:
        from engine.parsers.volatility.registry import canonical_plugin

        plugin = canonical_plugin(plugin)
    else:
        plugin = plugin_name(plugin)
    try:
        payload = path.read_bytes()
        data = json.loads(
            payload.decode("utf-8-sig"),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"Invalid JSON {value}")),
            object_pairs_hook=unique_object,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise VolatilityImportError(f"Cannot read Volatility JSON {path}: {exc}") from exc
    if not isinstance(data, list) or (not data and not extended):
        raise VolatilityImportError(f"{path}: expected a nonempty Volatility 3 JSON row array")
    digest = hashlib.sha256(payload).hexdigest()
    artifact = SourceArtifact(
        artifact_id=f"sha256:{digest}",
        kind="volatility_json",
        path=str(path.resolve()),
        sha256=digest,
        size=len(payload),
    )
    rows = []

    def visit(items: list, prefix: str = "", parent: int | None = None, depth: int = 0):
        if depth > 64:
            raise VolatilityImportError(f"{path}: JSON tree exceeds maximum depth 64")
        for index, item in enumerate(items):
            locator = f"{prefix}/{index}"
            if not isinstance(item, dict) or "event_id" in item:
                raise VolatilityImportError(f"{path}#{locator}: not a Volatility JSON row")
            children = item.get("__children", [])
            if not isinstance(children, list):
                raise VolatilityImportError(f"{path}#{locator}: __children must be an array")
            raw = {key: value for key, value in item.items() if key != "__children"}
            provenance = Provenance(
                source_artifact=artifact,
                raw_reference=RawReference(artifact_id=artifact.artifact_id, locator=locator),
                parser=ParserInfo(name="Volatility3Adapter", version=VERSION),
                tool="volatility3",
                tool_version=context.volatility_version,
                plugin=plugin,
                memory_image_id=context.memory_image_id,
                extraction_timestamp=context.extraction_timestamp,
                row_index=len(rows),
                raw=raw,
            )
            row = ExportRow(plugin, raw, provenance, parent if plugin == "windows.pstree" else None)
            rows.append(row)
            try:
                pid = integer(
                    get(raw, "PID", "Pid", "pid"),
                    "PID",
                    not extended and plugin != "windows.netscan",
                    2**32 - 1,
                )
            except ValueError as exc:
                raise row.error(str(exc)) from exc
            visit(children, locator + "/__children", pid, depth + 1)

    visit(data)
    return rows
