"""Merge external Volatility exports into validated, provenance-bearing Events."""

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

from engine.normalization import normalize_event
from engine.normalization.windows import path_key
from engine.parsers.volatility.rows import (
    PLUGINS,
    ExportRow,
    ImportContext,
    ImportResult,
    VolatilityImportError,
    get,
    integer,
    plugin_name,
    read_rows,
    string,
    timestamp,
)
from schemas.events import Event, Process, Provenance


def identity(kind: str, *parts) -> str:
    content = json.dumps(parts, sort_keys=True, default=str, ensure_ascii=False)
    return f"VOL-{kind}-{hashlib.sha256(content.encode()).hexdigest()[:24]}"


def unique_provenance(items: list[Provenance]) -> list[Provenance]:
    found = {}
    for item in items:
        key = (
            item.plugin,
            item.source_artifact.path,
            item.source_artifact.sha256,
            item.raw_reference.locator,
        )
        found[key] = item
    return [found[key] for key in sorted(found)]


@dataclass
class ProcessRecord:
    pid: int
    values: dict = field(default_factory=dict)
    rows: list[ExportRow] = field(default_factory=list)
    offsets: set[int] = field(default_factory=set)
    exit_time: datetime | None = None
    process: Process | None = None


class Volatility3Adapter:
    name = "Volatility3Adapter"
    version = "0.2.0"

    def __init__(self, context: ImportContext):
        self.context = context

    def load_file(self, path: Path, plugin: str) -> ImportResult:
        return self.load_exports([(plugin, path)])

    def load_directory(self, path: Path) -> ImportResult:
        exports = []
        for filename in sorted(path.glob("*.json")):
            stem = filename.stem
            plugin = stem if stem.startswith("windows.") else f"windows.{stem}"
            exports.append((plugin_name(plugin), filename))
        if not exports:
            raise VolatilityImportError(f"No supported JSON exports in directory: {path}")
        return self.load_exports(exports)

    def load_exports(self, exports: list[tuple[str, Path]]) -> ImportResult:
        if not exports:
            raise VolatilityImportError("No Volatility exports supplied")
        # Validate the entire batch before emitting any Event or touching a database.
        ordered = sorted(
            [(plugin_name(plugin), Path(path)) for plugin, path in exports],
            key=lambda pair: (PLUGINS.index(pair[0]), str(pair[1])),
        )
        rows = [row for plugin, path in ordered for row in read_rows(path, plugin, self.context)]
        warnings: list[str] = []
        if not self.context.volatility_version:
            warnings.append("Volatility version was not supplied; tool_version is null")
        process_rows = [row for row in rows if row.plugin in PLUGINS[:3]]
        records = self._processes(process_rows)
        by_pid: dict[int, list[ProcessRecord]] = defaultdict(list)
        for record in records:
            by_pid[record.pid].append(record)
        for record in records:
            self._parent(record, by_pid, warnings)
        events = []
        for record in records:
            assert record.process is not None
            created = record.process.creation_time
            events.append(
                self._event(
                    identity("PROCESS", record.process.instance_id),
                    "process_start" if created else "process_observation",
                    created,
                    "process_creation",
                    [row.provenance for row in record.rows],
                    process=record.process.model_dump(mode="json"),
                    attributes={
                        "eprocess_offsets": sorted(record.offsets),
                        "exit_time": record.exit_time.isoformat() if record.exit_time else None,
                    },
                )
            )
        observations: dict[str, Event] = {}
        for row in rows:
            if row.plugin in PLUGINS[:3]:
                continue
            try:
                event = (
                    self._socket(row, by_pid, warnings)
                    if row.plugin == "windows.netscan"
                    else self._module(row, by_pid, warnings)
                )
            except ValueError as exc:
                raise row.error(str(exc)) from exc
            if event.event_id in observations:
                previous = observations[event.event_id]
                previous.provenance = unique_provenance([*previous.provenance, *event.provenance])
            else:
                observations[event.event_id] = event
        events.extend(observations.values())
        if not events:
            raise VolatilityImportError("No usable Volatility events found")
        fallback = sum(event.timestamp_semantics == "extraction_time" for event in events)
        if fallback:
            warnings.append(
                f"{fallback} events lack event time; extraction timestamp is explicitly marked "
                "and receives no temporal score"
            )
        return ImportResult(
            events=sorted(events, key=lambda event: (event.timestamp, event.event_id)),
            warnings=sorted(set(warnings)),
            input_files=len(ordered),
            input_rows=len(rows),
        )

    def _process_values(self, row: ExportRow) -> dict:
        raw = row.raw
        pid = integer(get(raw, "PID", "Pid", "pid"), "PID", True, 2**32 - 1)
        name = string(get(raw, "ImageFileName", "Process", "Name"), "process name", True)
        created = timestamp(get(raw, "CreateTime", "Created", "Create Time"), "CreateTime")
        ppid = integer(get(raw, "PPID", "Ppid", "ppid"), "PPID", maximum=2**32 - 1)
        if row.parent_pid is not None:
            if ppid is not None and ppid != row.parent_pid:
                raise VolatilityImportError("PSTree hierarchy disagrees with explicit PPID")
            ppid = row.parent_pid
        if row.plugin == "windows.cmdline" and not any(
            key in raw for key in ("Args", "CommandLine", "Command Line")
        ):
            raise VolatilityImportError("Not a cmdline export: missing Args column")
        if row.plugin in PLUGINS[:2] and not any(
            key in raw for key in ("ImageFileName", "PPID", "CreateTime", "Offset(V)", "Offset(P)")
        ):
            raise VolatilityImportError("Not a pslist/pstree export: missing process columns")
        return {
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "creation_time": created,
            "command_line": string(get(raw, "Args", "Cmd", "CommandLine", "Command Line"), "command line"),
            "path": string(get(raw, "Path", "ImagePathName"), "executable path"),
        }

    def _processes(self, rows: list[ExportRow]) -> list[ProcessRecord]:
        values = []
        lifetimes: dict[int, set[datetime]] = defaultdict(set)
        for row in rows:
            try:
                fields = self._process_values(row)
            except ValueError as exc:
                raise row.error(str(exc)) from exc
            values.append((row, fields))
            if fields["creation_time"]:
                lifetimes[fields["pid"]].add(fields["creation_time"])
        merged: dict[tuple, ProcessRecord] = {}
        for row, fields in values:
            pid, created = fields["pid"], fields["creation_time"]
            if created is None and len(lifetimes[pid]) > 1:
                raise row.error(f"PID {pid} has multiple lifetimes; untimed row cannot be merged safely")
            start = created or next(iter(lifetimes[pid]), None)
            record = merged.setdefault((pid, start), ProcessRecord(pid=pid))
            for key, value in fields.items():
                if value is None:
                    continue
                existing = record.values.get(key)
                left, right = existing, value
                if key in {"name", "path"}:
                    left, right = path_key(existing), path_key(value)
                if existing is not None and left != right:
                    raise row.error(f"Conflicting {key} for PID {pid}; refusing to discard an observation")
                record.values[key] = value
            # Physical and virtual offsets are distinct address spaces.
            # Only virtual offsets identify EPROCESS.
            try:
                offset = integer(get(row.raw, "Offset(V)", "Offset"), "EPROCESS offset")
                exit_time = timestamp(get(row.raw, "ExitTime", "Exit Time"), "ExitTime")
            except ValueError as exc:
                raise row.error(str(exc)) from exc
            if offset is not None:
                record.offsets.add(offset)
            if len(record.offsets) > 1:
                raise row.error(f"PID {pid} has conflicting EPROCESS offsets")
            if exit_time:
                if start and exit_time < start:
                    raise row.error("ExitTime precedes CreateTime")
                if record.exit_time and record.exit_time != exit_time:
                    raise row.error(f"PID {pid} has conflicting exit times")
                record.exit_time = exit_time
            record.rows.append(row)
        for (_, start), record in merged.items():
            record.values["creation_time"] = start
            marker = start.isoformat() if start else next(iter(record.offsets), "snapshot")
            record.process = Process(
                **record.values,
                exit_time=record.exit_time,
                instance_id=identity("INSTANCE", self.context.memory_image_id, record.pid, marker),
            )
        return list(merged.values())

    @staticmethod
    def _parent(record: ProcessRecord, by_pid: dict, warnings: list[str]):
        process = record.process
        assert process is not None
        if process.ppid is None or process.ppid == process.pid:
            return
        candidates = [candidate for candidate in by_pid.get(process.ppid, []) if candidate.process]
        if process.creation_time:
            candidates = [
                candidate
                for candidate in candidates
                if (
                    not candidate.process.creation_time
                    or candidate.process.creation_time <= process.creation_time
                )
                and (not candidate.exit_time or process.creation_time <= candidate.exit_time)
            ]
        if len(candidates) == 1:
            process.parent_instance_id = candidates[0].process.instance_id
        elif candidates:
            warnings.append(f"PID {process.pid}: parent PID {process.ppid} has ambiguous lifetimes")

    def _owner(self, row: ExportRow, by_pid: dict, observed: datetime | None, warnings: list[str]):
        pid = integer(get(row.raw, "PID", "Pid", "pid"), "PID", row.plugin == "windows.dlllist", 2**32 - 1)
        name = string(get(row.raw, "Owner", "Process", "ImageFileName"), "process owner")
        if pid is None:
            return None, [], "unavailable"
        candidates = by_pid.get(pid, [])
        if name:
            candidates = [record for record in candidates if path_key(record.process.name) == path_key(name)]
        if observed:
            candidates = [
                record
                for record in candidates
                if (not record.process.creation_time or record.process.creation_time <= observed)
                and (not record.exit_time or observed <= record.exit_time)
            ]
        if len(candidates) == 1:
            record = candidates[0]
            return record.process.model_copy(deep=True), [item.provenance for item in record.rows], "resolved"
        if by_pid.get(pid):
            warnings.append(
                f"{row.plugin} row {row.provenance.raw_reference.locator}: "
                f"PID {pid} owner is ambiguous or conflicts with lifetime/name"
            )
        # Preserve reported PID/name without falsely sharing a resolved identity.
        instance = identity(
            "UNRESOLVED",
            self.context.memory_image_id,
            row.plugin,
            row.provenance.source_artifact.sha256,
            row.provenance.raw_reference.locator,
        )
        return Process(pid=pid, name=name, instance_id=instance), [], "unresolved"

    def _event(
        self,
        event_id: str,
        kind: str,
        time: datetime | None,
        semantics: str,
        provenance: list[Provenance],
        **fields,
    ) -> Event:
        primary = provenance[0]
        return normalize_event(
            {
                "event_id": event_id,
                "source": "memory",
                "type": kind,
                "timestamp": time or self.context.extraction_timestamp,
                "timestamp_semantics": semantics if time else "extraction_time",
                "hostname": self.context.hostname,
                "parser": {"name": self.name, "version": self.version},
                "source_artifact": primary.source_artifact.model_dump(mode="json"),
                "raw_reference": primary.raw_reference.model_dump(mode="json"),
                "raw": primary.raw,
                "provenance": [item.model_dump(mode="json") for item in unique_provenance(provenance)],
                **fields,
            }
        )

    def _socket(self, row: ExportRow, by_pid: dict, warnings: list[str]) -> Event:
        raw = row.raw
        protocol = string(get(raw, "Proto", "Protocol"), "Proto", True)
        assert protocol is not None
        transport = protocol.upper().removesuffix("V4").removesuffix("V6").removesuffix("V?")
        if transport not in {"TCP", "UDP"}:
            raise VolatilityImportError(f"Unsupported network protocol: {protocol}")
        if not any(key in raw for key in ("LocalAddr", "LocalAddress")):
            raise VolatilityImportError("Not a netscan export: missing LocalAddr column")

        def address(*names):
            value = string(get(raw, *names), names[0])
            if value in (None, "*"):
                return None
            return str(ip_address(value[1:-1] if value.startswith("[") and value.endswith("]") else value))

        network = {
            "src_ip": address("LocalAddr", "LocalAddress"),
            "src_port": integer(get(raw, "LocalPort"), "LocalPort", maximum=65535),
            "dst_ip": address("ForeignAddr", "ForeignAddress", "RemoteAddr"),
            "dst_port": integer(get(raw, "ForeignPort", "RemotePort"), "ForeignPort", maximum=65535),
            "protocol": transport,
            "state": string(get(raw, "State"), "State"),
        }
        if network["src_ip"] is None and network["dst_ip"] is None:
            raise VolatilityImportError("No usable local or remote socket address")
        observed = timestamp(get(raw, "Created", "CreateTime"), "Created")
        offset = integer(get(raw, "Offset", "Offset(V)"), "socket offset")
        process, provenance, association = self._owner(row, by_pid, observed, warnings)
        event_id = identity(
            "SOCKET",
            self.context.memory_image_id,
            network,
            process.pid if process else None,
            observed,
            offset,
        )
        return self._event(
            event_id,
            "socket",
            observed,
            "socket_creation",
            [row.provenance, *provenance],
            process=process.model_dump(mode="json") if process else None,
            network=network,
            attributes={
                "socket_offset": offset,
                "original_protocol": protocol,
                "owner_association": association,
            },
        )

    def _module(self, row: ExportRow, by_pid: dict, warnings: list[str]) -> Event:
        raw = row.raw
        if not any(key in raw for key in ("Base", "DllBase")):
            raise VolatilityImportError("Not a dlllist export: missing Base column")
        path = string(get(raw, "Path", "FullDllName"), "DLL path")
        name = string(get(raw, "Name", "BaseDllName"), "DLL name")
        if not path and not name:
            raise VolatilityImportError("DLL row has neither path nor name")
        base = integer(get(raw, "Base", "DllBase"), "DLL base address")
        size = integer(get(raw, "Size", "SizeOfImage"), "DLL size")
        observed = timestamp(get(raw, "LoadTime", "Load Time"), "LoadTime")
        process, provenance, association = self._owner(row, by_pid, observed, warnings)
        assert process is not None
        event_id = identity(
            "DLL", self.context.memory_image_id, process.pid, base, path_key(path or name), size, observed
        )
        return self._event(
            event_id,
            "module_load",
            observed,
            "module_load",
            [row.provenance, *provenance],
            process=process.model_dump(mode="json"),
            file={"path": path, "name": name},
            module={"base_address": base, "size": size},
            attributes={"owner_association": association},
        )
