"""Disk artifact normalization for documented exports and optional binary readers."""

import ntpath
import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

from engine.ingestion.evidence import (
    ArtifactError,
    DependencyUnavailable,
    EvidenceReader,
    boolean,
    number,
    parse_time,
    pick,
    text_value,
)
from engine.normalization.windows import path_key
from schemas.events import Event, Source
from schemas.imports import ArtifactContext, ImportBatch, ParserRun, RunStatus

KINDS = {
    "mft": "$MFT",
    "usn": "$UsnJrnl",
    "prefetch": "Prefetch",
    "evtx": "EVTX",
    "amcache": "amcache",
    "file": "file_content",
}
USN_FLAGS = {
    0x1: "DATA_OVERWRITE",
    0x2: "DATA_EXTEND",
    0x4: "DATA_TRUNCATION",
    0x10: "NAMED_DATA_OVERWRITE",
    0x20: "NAMED_DATA_EXTEND",
    0x40: "NAMED_DATA_TRUNCATION",
    0x100: "FILE_CREATE",
    0x200: "FILE_DELETE",
    0x400: "EA_CHANGE",
    0x800: "SECURITY_CHANGE",
    0x1000: "RENAME_OLD_NAME",
    0x2000: "RENAME_NEW_NAME",
    0x4000: "INDEXABLE_CHANGE",
    0x8000: "BASIC_INFO_CHANGE",
    0x10000: "HARD_LINK_CHANGE",
    0x20000: "COMPRESSION_CHANGE",
    0x40000: "ENCRYPTION_CHANGE",
    0x80000: "OBJECT_ID_CHANGE",
    0x100000: "REPARSE_POINT_CHANGE",
    0x200000: "STREAM_CHANGE",
    0x80000000: "CLOSE",
}


def string_list(value, field: str, delimiter: str = r"[|;\n]") -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    if isinstance(value, str):
        return [item.strip() for item in re.split(delimiter, value) if item.strip()]
    raise ArtifactError(f"{field} must be a list or delimited text")


def reference(value) -> tuple[int | None, int | None]:
    if value in (None, ""):
        return None, None
    if isinstance(value, str) and re.fullmatch(r"\d+-\d+", value):
        left, right = value.split("-")
        return int(left), int(right)
    parsed = number(value, "file reference", True, maximum=2**64 - 1)
    return parsed & ((1 << 48) - 1), parsed >> 48


def reason_flags(value) -> list[str]:
    if isinstance(value, int) or isinstance(value, str) and re.fullmatch(r"(?:0x[0-9a-fA-F]+|\d+)", value):
        parsed = number(value, "USN reason", True)
        result = [name for flag, name in USN_FLAGS.items() if parsed & flag]
        remaining = parsed & ~sum(USN_FLAGS)
        if remaining:
            result.append(f"UNKNOWN_{remaining:#x}")
        return result
    result = string_list(value, "USN reasons", r"[|,;\s]+")
    aliases = {name.replace("_", "").casefold(): name for name in USN_FLAGS.values()}
    return [aliases.get(name.replace("_", "").casefold(), name.upper()) for name in result]


class DiskArtifactAdapter:
    def __init__(self, context: ArtifactContext, mft_events: list[Event] | None = None):
        self.context, self.mft_events = context, mft_events or []

    def load_file(self, path: Path, kind: str) -> ImportBatch:
        if kind not in KINDS:
            raise ArtifactError(f"Unsupported disk artifact: {kind}")
        run = ParserRun(parser=f"{kind.upper()}Adapter", source=Source.DISK, status=RunStatus.FAILED)
        batch = ImportBatch(runs=[run])
        try:
            reader = EvidenceReader(Path(path), Source.DISK, KINDS[kind], self.context, run.parser)
            run.artifact = reader.artifact
            if kind == "file":
                events = [
                    reader.event(
                        "bytes:0",
                        {"sha256": reader.artifact.sha256, "size": reader.artifact.size},
                        0,
                        "file_observed",
                        file={
                            "path": self.context.logical_path,
                            "name": Path(path).name,
                            "sha256": reader.artifact.sha256,
                            "size": reader.artifact.size,
                        },
                    )
                ]
                records = [("bytes:0", {})]
            else:
                suffix = Path(path).suffix.casefold()
                if suffix in {".json", ".csv"}:
                    records = reader.rows()
                elif kind == "evtx" and suffix == ".xml":
                    records = xml_records(Path(path).read_text(encoding="utf-8-sig"))
                else:
                    from engine.collectors.disk.raw import read_binary

                    records, warnings = read_binary(Path(path), kind, self.context)
                    run.warnings.extend(warnings)
                events = []
                for index, (locator, row) in enumerate(records):
                    try:
                        events.extend(getattr(self, f"_{kind}")(reader, locator, row, index))
                    except ValueError as exc:
                        raise ArtifactError(f"{path}#{locator}: {exc}") from exc
            if not records:
                raise ArtifactError(f"No {kind} records found; input was not imported")
            if kind == "mft":
                self._resolve_mft(events)
            batch.events = events
            run.status, run.row_count, run.event_count = RunStatus.SUCCESS, len(records), len(events)
        except DependencyUnavailable as exc:
            run.status, run.error = RunStatus.UNAVAILABLE, str(exc)
        except Exception as exc:
            run.error = f"{type(exc).__name__}: {exc}"
        run.finished_at = datetime.now(UTC)
        return batch

    def _path(self, row, name: str | None) -> str | None:
        path = text_value(pick(row, "FullPath", "Full Path", "Path"), "FullPath")
        parent = text_value(pick(row, "ParentPath"), "ParentPath")
        if not path and parent and name:
            path = ntpath.join(parent, name)
        if path and not ntpath.splitdrive(path)[0] and self.context.mount_point:
            path = ntpath.join(self.context.mount_point, path.lstrip(".\\/"))
        return path

    def _file(self, row, name=None) -> dict:
        record, sequence = reference(pick(row, "FileReferenceNumber", "FileReference"))
        parent, parent_sequence = reference(pick(row, "ParentFileReferenceNumber", "ParentReference"))
        return {
            "name": name,
            "path": self._path(row, name),
            "volume_id": self.context.volume_id,
            "record_number": number(pick(row, "EntryNumber", "RecordNumber"), "EntryNumber")
            if pick(row, "EntryNumber", "RecordNumber") is not None
            else record,
            "sequence_number": number(pick(row, "SequenceNumber"), "SequenceNumber")
            if pick(row, "SequenceNumber") is not None
            else sequence,
            "parent_record": number(pick(row, "ParentEntryNumber", "ParentRecord"), "ParentEntryNumber")
            if pick(row, "ParentEntryNumber", "ParentRecord") is not None
            else parent,
            "parent_sequence": number(pick(row, "ParentSequenceNumber"), "ParentSequenceNumber")
            if pick(row, "ParentSequenceNumber") is not None
            else parent_sequence,
            "size": number(pick(row, "FileSize", "Size"), "FileSize"),
            "sha256": text_value(pick(row, "SHA256"), "SHA256"),
        }

    def _mft(self, reader, locator, row, index):
        name = text_value(pick(row, "FileName", "Name", required=True), "FileName", True)
        file = self._file(row, name)
        if file["record_number"] is None:
            raise ArtifactError("MFT requires EntryNumber or FileReferenceNumber")
        file["allocated"] = boolean(pick(row, "InUse", "Allocated"), "InUse")
        file["flags"] = string_list(pick(row, "SiFlags", "Flags", "FileAttributes"), "Flags", r"[|,;]+")
        for target, suffix in [("si_timestamps", "0x10"), ("fn_timestamps", "0x30")]:
            values = {}
            for field, name in [
                ("created", "Created"),
                ("modified", "LastModified"),
                ("changed", "LastRecordChange"),
                ("accessed", "LastAccess"),
            ]:
                value = parse_time(
                    pick(row, name + suffix, f"{target[:2]}_{field}"), self.context, name + suffix
                )
                if value:
                    values[field] = value
            file[target] = values
        observed = file["si_timestamps"].get("created")
        return [
            reader.event(
                locator,
                row,
                index,
                "file_observed",
                observed,
                file=file,
                timestamp_semantics="file_creation" if observed else "extraction_time",
                timestamp_precision=0.0000001,
                attributes={
                    "source_offset": pick(row, "SourceOffset", "Offset", "OffsetToData"),
                    "timestamp_field": "SI.Created" if observed else "extracted_at",
                },
            )
        ]

    def _resolve_mft(self, events):
        records = {(event.file.record_number, event.file.sequence_number): event for event in events}

        def resolve(event, trail):
            file = event.file
            if file.path:
                return file.path
            identity = (file.record_number, file.sequence_number)
            if identity in trail or len(trail) > 128:
                return None
            if file.record_number == 5:
                return self.context.mount_point
            parent = records.get((file.parent_record, file.parent_sequence))
            if parent:
                base = resolve(parent, trail | {identity})
                if base and file.name:
                    file.path = ntpath.join(base, file.name)
                    event.provenance.extend(p for p in parent.provenance if p not in event.provenance)
                    event.metadata["path_resolution"] = "MFT parent record and sequence"
            return file.path

        for event in events:
            resolve(event, set())

    def _usn(self, reader, locator, row, index):
        version = number(pick(row, "MajorVersion"), "MajorVersion") or 2
        name = text_value(pick(row, "Name", "FileName", required=version != 4), "Name", version != 4)
        file = self._file(row, name)
        if reference128 := pick(row, "FileReference128"):
            file["file_id128"] = reference128
        if file["record_number"] is None and not file.get("file_id128"):
            raise ArtifactError("USN requires EntryNumber or FileReferenceNumber")
        usn = number(pick(row, "UpdateSequenceNumber", "USN"), "USN", True)
        observed = parse_time(pick(row, "UpdateTimestamp", "Timestamp", required=version != 4), self.context)
        flags = reason_flags(pick(row, "UpdateReasons", "Reason", "Reasons", required=True))
        if not flags:
            raise ArtifactError("USN reasons are empty")
        event_type = "usn_record"
        for flag, target in [
            ("FILE_DELETE", "file_deleted"),
            ("FILE_CREATE", "file_created"),
            ("RENAME_OLD_NAME", "file_rename_old"),
            ("RENAME_NEW_NAME", "file_rename_new"),
            ("DATA_EXTEND", "file_modified"),
            ("DATA_OVERWRITE", "file_modified"),
            ("BASIC_INFO_CHANGE", "file_metadata_changed"),
        ]:
            if flag in flags:
                event_type = target
                break
        event = reader.event(
            locator,
            row,
            index,
            "usn_range_change" if version == 4 else event_type,
            observed,
            file=file,
            timestamp_semantics="extraction_time" if observed is None else "event_time",
            timestamp_precision=0.0000001,
            journal={
                "version": version,
                "extents": row.get("Extents", []),
                "remaining_extents": row.get("RemainingExtents"),
                "usn": usn,
                "reasons": flags,
                "source_info": str(pick(row, "SourceInfo")) if pick(row, "SourceInfo") is not None else None,
                "file_reference": str(pick(row, "FileReferenceNumber", "FileReference", "FileReference128"))
                if pick(row, "FileReferenceNumber", "FileReference", "FileReference128") is not None
                else None,
                "parent_reference": str(
                    pick(row, "ParentFileReferenceNumber", "ParentReference", "ParentReference128")
                )
                if pick(row, "ParentFileReferenceNumber", "ParentReference", "ParentReference128") is not None
                else None,
            },
            attributes={"source_offset": pick(row, "OffsetToData", "SourceOffset", "Offset")},
        )
        candidates = [
            other
            for other in self.mft_events
            if other.file
            and self.context.volume_id
            and other.file.volume_id == self.context.volume_id
            and other.hostname == event.hostname
            and other.file.sequence_number is not None
            and other.file.record_number == file["record_number"]
            and other.file.sequence_number == file["sequence_number"]
        ]
        paths = {other.file.path for other in candidates if other.file.path}
        # Historical rename names must not be overwritten with the current MFT name.
        if not event.file.path and len(paths) == 1 and not any(flag.startswith("RENAME_") for flag in flags):
            candidate = next(iter(paths))
            if ntpath.basename(path_key(candidate)) == path_key(name):
                event.file.path = candidate
                event.provenance.extend(
                    p for other in candidates for p in other.provenance if p not in event.provenance
                )
                event.metadata["path_resolution"] = "MFT volume/record/sequence/name match"
        return [event]

    def _prefetch(self, reader, locator, row, index):
        executable = text_value(
            pick(row, "ExecutableName", "Executable", required=True), "ExecutableName", True
        )
        references = string_list(pick(row, "FilesLoaded", "ReferencedFiles", "Files"), "FilesLoaded")
        directories = string_list(pick(row, "Directories", "ReferencedDirectories"), "Directories")
        times = []
        candidates = pick(row, "ExecutionTimes") or [
            pick(row, "LastRun", "LastExecutionTime"),
            *[pick(row, f"PreviousRun{i}") for i in range(7)],
        ]
        if not isinstance(candidates, list):
            raise ArtifactError("ExecutionTimes must be an array")
        for value in candidates:
            timestamp = parse_time(value, self.context, "execution time")
            if timestamp and timestamp not in times:
                times.append(timestamp)
        volumes = pick(row, "Volumes") or []
        if not isinstance(volumes, list):
            raise ArtifactError("Volumes must be an array")
        volumes = list(volumes)
        for ordinal in range(8):
            name = pick(row, f"Volume{ordinal}Name")
            if name:
                volumes.append(
                    {
                        "name": name,
                        "serial": pick(row, f"Volume{ordinal}Serial"),
                        "created": pick(row, f"Volume{ordinal}Created"),
                    }
                )
        prefetch = {
            "executable": executable,
            "executable_path": text_value(pick(row, "ExecutablePath"), "ExecutablePath"),
            "prefetch_hash": text_value(pick(row, "Hash", "PrefetchHash"), "PrefetchHash"),
            "run_count": number(pick(row, "RunCount"), "RunCount"),
            "execution_times": times,
            "directories": directories,
            "volumes": volumes,
        }
        # Recorded executions get separate times; references do not prove file execution.
        return [
            reader.event(
                locator,
                row,
                index,
                "prefetch_execution" if when else "prefetch_observation",
                when,
                suffix=str(when),
                prefetch=prefetch,
                file={
                    "path": text_value(pick(row, "SourceFilename", "SourceFile"), "SourceFilename"),
                    "references": references,
                },
                timestamp_precision=0.0000001,
                timestamp_semantics="process_execution" if when else "extraction_time",
            )
            for when in sorted(times) or [None]
        ]

    def _amcache(self, reader, locator, row, index):
        path = text_value(pick(row, "FullPath", "LowerCaseLongPath", "Path", required=True), "FullPath", True)
        observed = parse_time(
            pick(row, "FileKeyLastWriteTimestamp", "KeyLastWriteTimestamp", "LastWriteTime"), self.context
        )
        digest = text_value(pick(row, "SHA1", "FileId"), "SHA1")
        if digest and len(digest) == 44 and digest.startswith("0000"):
            digest = digest[4:]
        return [
            reader.event(
                locator,
                row,
                index,
                "registry_artifact_observation",
                observed,
                file={
                    "path": path,
                    "size": number(pick(row, "Size", "FileSize"), "Size"),
                    "sha256": text_value(pick(row, "SHA256"), "SHA256"),
                },
                hash={"sha1": digest} if digest else None,
                registry={
                    "artifact": "amcache",
                    "hive": text_value(pick(row, "Hive"), "Hive"),
                    "path": text_value(pick(row, "KeyPath"), "KeyPath"),
                    "last_write_time": observed,
                },
                timestamp_semantics="registry_write" if observed else "extraction_time",
            )
        ]

    def _evtx(self, reader, locator, row, index):
        identifier = number(pick(row, "EventId", "Event ID", required=True), "EventId", True)
        provider = text_value(pick(row, "Provider", "ProviderName", required=True), "Provider", True)
        observed = parse_time(pick(row, "TimeCreated", "Timestamp", required=True), self.context)
        data = row.get("EventData", row)
        if not isinstance(data, dict):
            raise ArtifactError("EventData must be an object")
        sysmon = "sysmon" in provider.casefold()
        security_creation = (
            provider.casefold() == "microsoft-windows-security-auditing" and identifier == 4688
        )
        pid = number(
            pick(data, "NewProcessId") if security_creation else pick(data, "ProcessId", "PID"),
            "PID",
            maximum=2**32 - 1,
        )
        ppid = number(
            pick(data, "ProcessId", "CreatorProcessId")
            if security_creation
            else pick(data, "ParentProcessId", "PPID"),
            "PPID",
            maximum=2**32 - 1,
        )
        image = text_value(
            pick(data, "NewProcessName") if security_creation else pick(data, "Image", "ProcessImage"),
            "Image",
        )
        command = text_value(pick(data, "CommandLine"), "CommandLine")
        event_type = "event_log"
        if security_creation or sysmon and identifier == 1:
            event_type = "process_start"
        elif sysmon:
            event_type = {
                3: "network_connection",
                7: "module_load",
                11: "file_created",
                12: "registry_activity",
                13: "registry_activity",
                14: "registry_activity",
            }.get(identifier, event_type)
        elif "powershell" in provider.casefold():
            event_type = "powershell_event"
        fields = {
            "event_log": {
                "event_id": identifier,
                "provider": provider,
                "channel": text_value(pick(row, "Channel"), "Channel"),
                "record_id": number(pick(row, "RecordId", "EventRecordId"), "RecordId"),
                "computer": text_value(pick(row, "Computer"), "Computer"),
            }
        }
        host = text_value(pick(row, "Computer"), "Computer") or self.context.hostname
        if pid is not None:
            fields["process"] = {
                "pid": pid,
                "ppid": ppid,
                "name": ntpath.basename(image) if image else None,
                "path": image,
                "command_line": command,
                "creation_time": observed if event_type == "process_start" else None,
            }
        path = text_value(pick(data, "TargetFilename", "FilePath", "ImageLoaded", "Path"), "FilePath")
        if path:
            fields["file"] = {"path": path}
        registry = text_value(pick(data, "TargetObject", "RegistryPath"), "RegistryPath")
        if registry:
            fields["registry"] = {
                "artifact": "event_log",
                "path": registry,
                "value_data": pick(data, "Details", "ValueData"),
            }
        src, dst = pick(data, "SourceIp", "SrcIp"), pick(data, "DestinationIp", "DstIp", "IpAddress")
        if src or dst:
            fields["network"] = {
                "src_ip": src,
                "dst_ip": dst,
                "src_port": number(pick(data, "SourcePort", "SrcPort"), "SourcePort", maximum=65535),
                "dst_port": number(
                    pick(data, "DestinationPort", "DstPort", "IpPort"), "DestinationPort", maximum=65535
                ),
                "protocol": text_value(pick(data, "Protocol"), "Protocol"),
            }
        user = text_value(
            pick(data, "User") or pick(data, "TargetUserName") or pick(data, "SubjectUserName"), "User"
        )
        sid = text_value(
            pick(row, "UserId") or pick(data, "TargetUserSid") or pick(data, "SubjectUserSid"), "UserId"
        )
        if user or sid:
            fields["user"] = {"name": user, "sid": sid}
        if identifier == 7045 and provider.casefold() in {
            "service control manager",
            "microsoft-windows-service-control-manager",
        }:
            name = text_value(pick(data, "ServiceName", required=True), "ServiceName", True)
            fields["service"] = {
                "name": name,
                "binary_path": text_value(pick(data, "ImagePath"), "ImagePath"),
                "start_type": text_value(pick(data, "StartType"), "StartType"),
            }
            event_type = "service_installation"
        return [reader.event(locator, row, index, event_type, observed, hostname=host, **fields)]


def xml_records(content: str) -> list[tuple[str, dict]]:
    if "<!DOCTYPE" in content.upper() or "<!ENTITY" in content.upper():
        raise ArtifactError("DTD/entity declarations are not supported in Event XML")
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ArtifactError(f"Malformed Event XML: {exc}") from exc
    elements = [root] if root.tag.rsplit("}", 1)[-1] == "Event" else root.findall(".//{*}Event")
    rows = []
    for index, element in enumerate(elements):
        system = element.find("{*}System")
        if system is None:
            raise ArtifactError("Event XML has no System element")

        def value(name, system=system):
            child = system.find("{*}" + name)
            return child.text if child is not None else None

        provider, created, security = (
            system.find("{*}Provider"),
            system.find("{*}TimeCreated"),
            system.find("{*}Security"),
        )
        data = {}
        for entry in element.findall(".//{*}EventData/{*}Data"):
            name = entry.get("Name") or f"unnamed_{len(data)}"
            if name in data:
                raise ArtifactError(f"Duplicate EventData name: {name}")
            data[name] = entry.text or ""
        row = {
            "EventId": value("EventID"),
            "RecordId": value("EventRecordID"),
            "Channel": value("Channel"),
            "Computer": value("Computer"),
            "Provider": provider.get("Name") if provider is not None else None,
            "TimeCreated": created.get("SystemTime") if created is not None else None,
            "UserId": security.get("UserID") if security is not None else None,
            "EventData": data,
            "OriginalXML": ET.tostring(element, encoding="unicode"),
        }
        rows.append((f"xml:event:{index}", row))
    if not rows:
        raise ArtifactError("No Event elements in XML")
    return rows
