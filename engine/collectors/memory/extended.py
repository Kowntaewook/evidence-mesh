"""Complete memory-export ingestion, composed with the stable five-plugin adapter."""

import json
from datetime import UTC, datetime
from pathlib import Path

from engine.collectors.memory.volatility import Volatility3Adapter, identity, unique_provenance
from engine.ingestion.evidence import (
    ArtifactError,
    address,
    boolean,
    digest_file,
    number,
    parse_time,
    pick,
    text_value,
)
from engine.normalization import normalize_event
from engine.normalization.windows import path_key
from engine.parsers.volatility.registry import SPECS, canonical_plugin, filename_plugin
from engine.parsers.volatility.rows import PLUGINS, ImportContext, read_rows
from schemas.events import Event, Process, Source, SourceArtifact
from schemas.imports import ArtifactContext, ImportBatch, ParserRun, RunStatus


class MemoryImportAdapter:
    """Preserves every plugin's outcome; one unavailable/failed plugin does not erase others."""

    def __init__(self, context: ArtifactContext):
        self.context = context
        self.memory_context = ImportContext(
            memory_image_id=context.acquisition_id,
            extraction_timestamp=context.extracted_at,
            hostname=context.hostname,
            volatility_version=context.tool_version,
        )
        self.legacy = Volatility3Adapter(self.memory_context)

    def load_directory(self, path: Path, expected: list[str] | None = None) -> ImportBatch:
        exports, errors = [], []
        for file in sorted(Path(path).glob("*.json")):
            try:
                exports.append((filename_plugin(file.stem), file))
            except ValueError as exc:
                errors.append(
                    ParserRun(
                        parser="Volatility3Adapter",
                        plugin=file.stem,
                        source=Source.MEMORY,
                        status=RunStatus.FAILED,
                        error=str(exc),
                        finished_at=datetime.now(UTC),
                    )
                )
        if not exports and not errors:
            raise ArtifactError(f"No Volatility JSON exports in {path}")
        result = self.load_exports(exports, expected)
        result.runs.extend(errors)
        return result

    def load_exports(self, exports: list[tuple[str, Path]], expected: list[str] | None = None) -> ImportBatch:
        batch = ImportBatch()
        loaded, legacy_exports = [], []
        for supplied, path in exports:
            run = ParserRun(
                parser="Volatility3Adapter", plugin=supplied, source=Source.MEMORY, status=RunStatus.FAILED
            )
            try:
                plugin = canonical_plugin(supplied)
                run.plugin = plugin
                digest, size = digest_file(Path(path))
                run.artifact = SourceArtifact(
                    artifact_id=f"sha256:{digest}",
                    kind="volatility_json",
                    path=str(Path(path).resolve()),
                    sha256=digest,
                    size=size,
                    imported_at=run.started_at,
                )
                rows = read_rows(Path(path), plugin, self.memory_context, extended=True)
                run.row_count = len(rows)
                for row in rows:
                    row.provenance.source_artifact = run.artifact
                    row.provenance.source = Source.MEMORY
                    row.provenance.acquisition_id = self.context.acquisition_id
                if plugin in PLUGINS:
                    if rows:
                        self.legacy.load_file(Path(path), plugin)  # validate before a joint merge
                        legacy_exports.append((plugin, Path(path)))
                loaded.append((plugin, rows, run))
                run.status = RunStatus.SUCCESS
            except (ValueError, OSError) as exc:
                run.error = str(exc)
            run.finished_at = datetime.now(UTC)
            batch.runs.append(run)
        if legacy_exports:
            try:
                result = self.legacy.load_exports(legacy_exports)
                batch.events.extend(result.events)
                for event in result.events:
                    event.artifact_type = "process" if event.type.startswith("process") else event.type
                    event.metadata = {"acquisition_id": self.context.acquisition_id}
                    for p in event.provenance:
                        source_run = next(
                            run
                            for run in batch.runs
                            if run.plugin == p.plugin
                            and run.artifact
                            and run.artifact.path == p.source_artifact.path
                        )
                        p.source_artifact = source_run.artifact
                        p.source = Source.MEMORY
                        p.acquisition_id = self.context.acquisition_id
                    if event.module and event.module.base_address is not None:
                        event.module.base_address_hex = hex(event.module.base_address)
                for plugin, _, run in loaded:
                    if plugin in PLUGINS:
                        run.event_count = sum(
                            any(p.plugin == plugin for p in e.provenance) for e in result.events
                        )
                        run.warnings.extend(result.warnings)
            except ValueError as exc:
                for plugin, _, run in loaded:
                    if plugin in PLUGINS:
                        run.status, run.error = RunStatus.FAILED, str(exc)
        owners = [event for event in batch.events if event.type in {"process_start", "process_observation"}]
        for plugin, rows, run in loaded:
            if plugin in PLUGINS:
                continue
            try:
                events = [self.convert(row, owners) for row in rows]
                batch.events.extend(events)
                run.event_count = len(events)
            except (ValueError, OSError) as exc:
                run.status, run.error = RunStatus.FAILED, str(exc)
            run.finished_at = datetime.now(UTC)
        requested = [canonical_plugin(name) for name in expected] if expected is not None else []
        supplied = {run.plugin for run in batch.runs}
        for plugin in requested:
            if plugin not in supplied:
                batch.runs.append(
                    ParserRun(
                        parser="Volatility3Adapter",
                        plugin=plugin,
                        source=Source.MEMORY,
                        status=RunStatus.SKIPPED,
                        error="No export supplied",
                        finished_at=datetime.now(UTC),
                    )
                )
        self._comparisons(batch)
        batch.events.sort(key=lambda event: (event.timestamp, event.event_id))
        return batch

    def _owner(self, row, owners: list[Event], observed=None):
        raw = row.raw
        pid = number(pick(raw, "PID"), "PID", maximum=2**32 - 1)
        if pid is None:
            return None, [], "not_reported"
        name = text_value(pick(raw, "Process", "ImageFileName"), "Process")
        candidates = [
            event
            for event in owners
            if event.process.pid == pid
            and (not name or path_key(event.process.name) == path_key(name))
            and (not observed or not event.process.creation_time or event.process.creation_time <= observed)
            and (not observed or not event.process.exit_time or observed <= event.process.exit_time)
        ]
        if len(candidates) == 1:
            return candidates[0].process.model_copy(deep=True), candidates[0].provenance, "resolved"
        return (
            Process(
                pid=pid,
                name=name,
                instance_id=identity(
                    "UNRESOLVED",
                    self.context.acquisition_id,
                    row.plugin,
                    row.provenance.source_artifact.sha256,
                    row.provenance.raw_reference.locator,
                ),
            ),
            [],
            "unresolved",
        )

    def convert(self, row, owners: list[Event]) -> Event:
        raw, plugin = row.raw, row.plugin
        fields, observed, kind, semantics = {}, None, plugin.rsplit(".", 1)[-1], "event_time"
        metadata = {"acquisition_id": self.context.acquisition_id, "acquisition_tool": "volatility3"}
        process, provenance, association = self._owner(row, owners)
        metadata["owner_association"] = association
        if plugin == "windows.psscan":
            # Scan results remain separate observations even when their lifetime matches pslist.
            values = self.legacy._process_values(row)
            observed = values["creation_time"]
            exited = parse_time(pick(raw, "ExitTime"), self.context, "ExitTime")
            candidates = [
                e
                for e in owners
                if e.process.pid == values["pid"]
                and observed is not None
                and e.process.creation_time == observed
                and path_key(e.process.name) == path_key(values["name"])
            ]
            instance = (
                candidates[0].process.instance_id
                if len(candidates) == 1
                else identity(
                    "SCAN",
                    self.context.acquisition_id,
                    values["pid"],
                    observed,
                    pick(raw, "Offset(P)", "Offset(V)", "Offset"),
                )
            )
            process = Process(**values, exit_time=exited, instance_id=instance)
            provenance = []
            kind, event_type, semantics = "process_scan", "process_scan", "process_creation"
        elif plugin == "windows.envars":
            if process is None:
                raise row.error("Missing PID")
            variable = text_value(pick(raw, "Variable", required=True), "Variable", True)
            value = raw.get("Value")
            if not isinstance(value, str):
                raise row.error("Value must be a string (empty is valid)")
            process.environment = {variable: value}
            metadata["environment_block"] = pick(raw, "Block")
            event_type = "environment_observation"
        elif plugin == "windows.handles":
            if process is None:
                raise row.error("Missing PID")
            handle_type = text_value(pick(raw, "Type", required=True), "Type", True)
            name = text_value(pick(raw, "Name"), "Name")
            offset = address(pick(raw, "Offset", "Object"), "Offset", True)
            fields["handle"] = {
                "type": handle_type,
                "name": name,
                "object_address": offset,
                "value": address(pick(raw, "HandleValue"), "HandleValue"),
                "granted_access": address(pick(raw, "GrantedAccess"), "GrantedAccess"),
            }
            if handle_type.casefold() == "file":
                fields["file"] = {"path": name, "file_object": offset}
            elif handle_type.casefold() == "key":
                fields["registry"] = {"artifact": "key_handle", "path": name}
            event_type = "handle_observation"
        elif plugin == "windows.filescan":
            fields["file"] = {
                "path": text_value(pick(raw, "Name", required=True), "Name", True),
                "file_object": address(pick(raw, "Offset"), "Offset", True),
            }
            event_type = "file_object_observation"
        elif plugin in {"windows.vadinfo", "windows.malware.malfind"}:
            if process is None:
                raise row.error("Missing PID")
            mapped = text_value(pick(raw, "File", "MappedFile"), "MappedFile")
            region = {
                "start": address(pick(raw, "Start VPN", "Start", "Address"), "Start", True),
                "end": address(pick(raw, "End VPN", "End"), "End"),
                "protection": text_value(pick(raw, "Protection"), "Protection"),
                "tag": text_value(pick(raw, "Tag"), "Tag"),
                "commit": number(pick(raw, "CommitCharge", "Commit"), "CommitCharge"),
                "private_memory": boolean(pick(raw, "PrivateMemory"), "PrivateMemory"),
                "mapped_file": mapped,
            }
            if region["end"] and int(region["end"], 16) < int(region["start"], 16):
                raise row.error("Memory region End precedes Start")
            if plugin.endswith("malfind"):
                for target, source in [("hex_preview", "Hexdump"), ("disassembly_preview", "Disasm")]:
                    value = pick(raw, source)
                    region[target] = value if isinstance(value, str) or value is None else json.dumps(value)
                kind = "suspicious_memory_region"
            fields["memory_region"] = region
            if mapped:
                fields["file"] = {"path": mapped}
            event_type = "memory_region_observation"
        elif plugin in {"windows.svcscan", "windows.svclist"}:
            name = text_value(pick(raw, "Name", "ServiceName", required=True), "ServiceName", True)
            binary = text_value(pick(raw, "Binary", "BinaryPath"), "Binary")
            fields["service"] = {
                "name": name,
                "display_name": text_value(pick(raw, "Display", "DisplayName"), "Display"),
                "state": text_value(pick(raw, "State"), "State"),
                "start_type": text_value(pick(raw, "Start", "StartType"), "Start"),
                "binary_path": binary,
                "pid": process.pid if process else None,
                "service_dll": text_value(pick(raw, "Dll", "ServiceDll"), "Dll"),
            }
            metadata["registry_binary"] = pick(raw, "Binary (Registry)")
            event_type = "service_observation"
        elif plugin in {"windows.registry.amcache", "windows.registry.userassist", "windows.shimcachemem"}:
            registry = {"artifact": kind}
            if kind == "amcache":
                if "EntryType" not in raw and "Path" not in raw:
                    raise row.error("Missing Amcache EntryType/Path columns")
                path = text_value(pick(raw, "Path"), "Path")
                observed = parse_time(pick(raw, "LastModifyTime"), self.context, "LastModifyTime")
                digest = text_value(pick(raw, "SHA1"), "SHA1")
                if digest:
                    digest = digest[4:] if len(digest) == 44 and digest.startswith("0000") else digest
                    fields["hash"] = {"sha1": digest}
                metadata["entry_type"] = pick(raw, "EntryType")
            elif kind == "userassist":
                path = text_value(pick(raw, "Name"), "Name")
                registry.update(
                    {
                        "hive": text_value(pick(raw, "Hive Name"), "Hive Name"),
                        "path": text_value(pick(raw, "Path", required=True), "Path", True),
                        "value_name": path,
                        "value_data": pick(raw, "Raw Data"),
                        "run_count": number(pick(raw, "Count"), "Count"),
                    }
                )
                observed = parse_time(pick(raw, "Last Updated"), self.context, "Last Updated")
                registry["last_write_time"] = parse_time(pick(raw, "Last Write Time"), self.context)
            else:
                path = text_value(pick(raw, "File Path", required=True), "File Path", True)
                observed = parse_time(pick(raw, "Last Modified"), self.context, "Last Modified")
                metadata["execution_flag"] = boolean(pick(raw, "Exec Flag"), "Exec Flag")
            fields["registry"] = registry
            if path:
                fields["file"] = {"path": path}
            event_type = "registry_artifact_observation"
        elif plugin in {"windows.modules", "windows.modscan"}:
            name = text_value(pick(raw, "Name", required=True), "Name", True)
            base = number(pick(raw, "Base"), "Base", True)
            path = text_value(pick(raw, "Path"), "Path")
            fields["module"] = {
                "name": name,
                "path": path,
                "base_address": base,
                "base_address_hex": hex(base),
                "size": number(pick(raw, "Size"), "Size"),
                "observation": kind,
            }
            if path:
                fields["file"] = {"path": path}
            event_type = "kernel_module_observation"
        elif plugin == "windows.driverscan":
            fields["driver"] = {
                "name": text_value(pick(raw, "Driver Name", "DriverName"), "Driver Name"),
                "path": text_value(pick(raw, "Name"), "Name"),
                "object_address": address(pick(raw, "Offset"), "Offset", True),
                "start": address(pick(raw, "Start"), "Start"),
                "size": number(pick(raw, "Size"), "Size"),
                "service_key": text_value(pick(raw, "Service Key"), "Service Key"),
            }
            event_type = "driver_observation"
        elif plugin == "windows.callbacks":
            fields["callback"] = {
                "type": text_value(pick(raw, "Type", required=True), "Type", True),
                "address": address(pick(raw, "Callback", "Address"), "Callback", True),
                "module": text_value(pick(raw, "Module"), "Module"),
                "symbol": text_value(pick(raw, "Symbol"), "Symbol"),
            }
            event_type = "callback_observation"
        elif plugin == "windows.dumpfiles":
            if not self.context.recovered_directory:
                raise row.error("dumpfiles requires recovered_directory to verify recovered bytes")
            root = Path(self.context.recovered_directory).resolve()
            output = text_value(pick(raw, "Result", "OutputPath", required=True), "Result", True)
            target = (root / output).resolve()
            if not target.is_relative_to(root):
                raise row.error("Recovered output path is outside recovered_directory")
            digest, size = digest_file(target)
            fields["file"] = {
                "path": text_value(pick(raw, "FileName"), "FileName"),
                "sha256": digest,
                "size": size,
                "file_object": address(pick(raw, "FileObject"), "FileObject", True),
            }
            metadata.update(
                {
                    "recovered_output": str(target),
                    "recovered_sha256": digest,
                    "recovered_size": size,
                    "cache": pick(raw, "Cache"),
                    "memory_offset": address(pick(raw, "MemoryOffset", "Offset"), "MemoryOffset"),
                }
            )
            event_type = "recovered_file"
        else:
            raise row.error(f"Unsupported plugin contract: {plugin}")
        primary = row.provenance
        return normalize_event(
            {
                "event_id": identity(
                    "OBS",
                    self.context.acquisition_id,
                    plugin,
                    primary.source_artifact.sha256,
                    primary.raw_reference.locator,
                ),
                "source": "memory",
                "type": event_type,
                "artifact_type": kind,
                "timestamp": observed or self.context.extracted_at,
                "timestamp_semantics": semantics if observed else "extraction_time",
                "hostname": self.context.hostname,
                "process": process.model_dump(mode="json") if process else None,
                "parser": {"name": "Volatility3Adapter", "version": "0.3.0"},
                "source_artifact": primary.source_artifact.model_dump(mode="json"),
                "raw_reference": primary.raw_reference.model_dump(),
                "raw": raw,
                "provenance": [p.model_dump(mode="json") for p in unique_provenance([primary, *provenance])],
                "metadata": metadata,
                **fields,
            }
        )

    @staticmethod
    def _comparisons(batch: ImportBatch):
        success = {run.plugin for run in batch.runs if run.status == RunStatus.SUCCESS}
        active = [event for event in batch.events if event.type in {"process_start", "process_observation"}]
        active_ids = {event.process.instance_id for event in active}
        scanned_ids = {event.process.instance_id for event in batch.events if event.type == "process_scan"}
        modules = {
            (event.artifact_type, event.module.base_address, path_key(event.module.name))
            for event in batch.events
            if event.type == "kernel_module_observation"
        }
        for event in batch.events:
            if event.type in {"process_start", "process_observation"}:
                event.metadata["pslist_found"] = any(p.plugin == "windows.pslist" for p in event.provenance)
                event.metadata["psscan_found"] = (
                    event.process.instance_id in scanned_ids if "windows.psscan" in success else None
                )
            if event.type == "process_scan":
                matching = event.process.instance_id in active_ids
                event.metadata["pslist_found"] = matching if "windows.pslist" in success else None
                event.metadata["psscan_found"] = True
                event.metadata["signal"] = (
                    "psscan_only" if "windows.pslist" in success and not matching else "scan_observation"
                )
            if event.type == "kernel_module_observation":
                counterpart = "modscan" if event.artifact_type == "modules" else "modules"
                matched = (counterpart, event.module.base_address, path_key(event.module.name)) in modules
                event.metadata[f"{counterpart}_found"] = (
                    matched if f"windows.{counterpart}" in success else None
                )
                event.metadata["signal"] = "module_list_comparison"


SUPPORTED_MEMORY_PLUGINS = tuple(spec.name for spec in SPECS)
