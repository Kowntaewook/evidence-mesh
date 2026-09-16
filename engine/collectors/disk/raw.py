"""Binary readers. They return records to the same disk normalization contracts."""

import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

from engine.ingestion.evidence import ArtifactError, DependencyUnavailable


def filetime(value: int) -> str | None:
    return (
        (datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=value // 10)).isoformat()
        if value
        else None
    )


def read_binary(path: Path, kind: str, context):
    if kind == "mft":
        return read_mft(path)
    if kind == "usn":
        return read_usn(path)
    if kind == "prefetch":
        return [("bytes:0", read_prefetch(path))], []
    if kind == "evtx":
        return read_evtx(path)
    if kind == "amcache":
        return read_amcache(path)
    raise DependencyUnavailable(f"No binary reader for {kind}")


def read_mft(path):
    try:
        from dissect.ntfs.mft import MftRecord
        from dissect.ntfs.util import segment_reference
    except ImportError as exc:
        raise DependencyUnavailable("Raw MFT requires dissect.ntfs") from exc
    rows, warnings = [], []
    with path.open("rb") as stream:
        first = stream.read(64)
        if first[:4] != b"FILE" or len(first) < 32:
            raise ArtifactError("Invalid MFT FILE header")
        record_size = struct.unpack_from("<I", first, 28)[0]
        if record_size not in {1024, 2048, 4096}:
            raise ArtifactError(f"Unsupported MFT record size: {record_size}")
        stream.seek(0)
        offset = 0
        while data := stream.read(record_size):
            if len(data) != record_size:
                raise ArtifactError(f"Truncated MFT record at {offset}")
            if not any(data):
                offset += record_size
                continue
            record = MftRecord.from_bytes(data)
            names = list(record.attributes.FILE_NAME)
            si = next(iter(record.attributes.STANDARD_INFORMATION), None)
            if not names:
                warnings.append(f"MFT record {offset // record_size} has no FILE_NAME; no file event emitted")
            for ordinal, name in enumerate(names):
                parent = name.attr.ParentDirectory
                row = {
                    "EntryNumber": offset // record_size,
                    "SequenceNumber": record.header.SequenceNumber,
                    "ParentEntryNumber": segment_reference(parent),
                    "ParentSequenceNumber": parent.SequenceNumber,
                    "FileName": name.file_name,
                    "FileSize": name.file_size,
                    "InUse": bool(int(record.header.Flags) & 1),
                    "SourceOffset": offset,
                    "SiFlags": str(si.file_attributes) if si else None,
                    "NameType": int(name.flags),
                }
                for attr, suffix in [(si, "0x10"), (name, "0x30")]:
                    if attr:
                        for target, field in [
                            ("Created", "creation_time"),
                            ("LastModified", "last_modification_time"),
                            ("LastRecordChange", "last_change_time"),
                            ("LastAccess", "last_access_time"),
                        ]:
                            row[target + suffix] = getattr(attr, field).isoformat()
                rows.append((f"bytes:{offset}/filename:{ordinal}", row))
            offset += record_size
    return rows, warnings


def read_usn(path):
    """Decode distinct USN layouts without truncating 128-bit file identifiers."""
    rows = []
    with path.open("rb") as stream:
        size, offset = path.stat().st_size, 0
        while offset < size:
            stream.seek(offset)
            header = stream.read(8)
            if header == b"\0" * 8:
                padding = header + stream.read(min(65528, size - offset - 8))
                first = next((i for i, value in enumerate(padding) if value), None)
                offset += len(padding) if first is None else first // 8 * 8
                continue
            if len(header) < 8:
                raise ArtifactError(f"Truncated USN header at {offset}")
            length, version, minor = struct.unpack("<IHH", header)
            if length < 8 or length % 8 or offset + length > size or length > 16 * 1024 * 1024:
                raise ArtifactError(f"Invalid USN record length at {offset}")
            if version not in {2, 3, 4} or minor:
                raise DependencyUnavailable(f"Unsupported USN layout {version}.{minor}")
            minimum = {2: 60, 3: 76, 4: 64}[version]
            if length < minimum:
                raise ArtifactError(f"Invalid USN record length at {offset}")
            data = header + stream.read(length - 8)
            width = 8 if version == 2 else 16
            reference = int.from_bytes(data[8 : 8 + width], "little")
            parent = int.from_bytes(data[8 + width : 8 + 2 * width], "little")
            position = 8 + 2 * width
            usn = struct.unpack_from("<q", data, position)[0]
            if usn < 0:
                raise ArtifactError("Negative USN sequence number")
            row = {"MajorVersion": version, "MinorVersion": minor, "USN": usn, "SourceOffset": offset}
            if version == 2:
                row.update(FileReferenceNumber=str(reference), ParentFileReferenceNumber=str(parent))
            else:
                row.update(FileReference128=f"0x{reference:032x}", ParentReference128=f"0x{parent:032x}")
            # NTFS-compatible low 64-bit identifiers can be joined; other 128-bit IDs stay opaque.
            for value, record_key, sequence_key in (
                (reference, "EntryNumber", "SequenceNumber"),
                (parent, "ParentEntryNumber", "ParentSequenceNumber"),
            ):
                if value < 2**64:
                    row[record_key], row[sequence_key] = value & ((1 << 48) - 1), value >> 48
            if version in {2, 3}:
                timestamp, reason, source_info = struct.unpack_from("<QII", data, position + 8)
                name_length, name_offset = struct.unpack_from("<HH", data, position + 32)
                if name_offset < minimum or name_length % 2 or name_offset + name_length > length:
                    raise ArtifactError(f"USN filename extends outside record at {offset}")
                row.update(
                    Timestamp=filetime(timestamp),
                    Name=data[name_offset : name_offset + name_length].decode("utf-16-le"),
                )
            else:
                reason, source_info, remaining, count, extent_size = struct.unpack_from("<IIIHH", data, 48)
                if extent_size != 16:
                    raise DependencyUnavailable(f"Unsupported USN v4 extent size {extent_size}")
                if 64 + count * extent_size > length:
                    raise ArtifactError("USN v4 extents extend outside record")
                extents = []
                for index in range(count):
                    start, extent_length = struct.unpack_from("<qq", data, 64 + index * 16)
                    if start < 0 or extent_length < 0:
                        raise ArtifactError("Negative USN v4 extent")
                    extents.append({"offset": start, "length": extent_length})
                row.update(Extents=extents, RemainingExtents=remaining)
            row.update(Reason=reason, SourceInfo=source_info)
            rows.append((f"bytes:{offset}", row))
            offset += length
    return rows, []


def read_prefetch(path):
    data = path.read_bytes()
    if data[:3] == b"MAM":
        from engine.collectors.disk.prefetch_compression import decompress_mam

        data = decompress_mam(data)
    if len(data) < 152 or data[4:8] != b"SCCA":
        raise ArtifactError("Invalid or truncated Prefetch SCCA header")

    def read(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise ArtifactError(f"Prefetch field outside file at {offset}")
        return struct.unpack_from(fmt, data, offset)[0]

    def string(offset, length):
        if offset < 0 or length < 0 or offset + length > len(data) or length % 2:
            raise ArtifactError("Prefetch string outside file")
        return data[offset : offset + length].decode("utf-16-le").rstrip("\0")

    version, declared = read("<I", 0), read("<I", 12)
    if declared != len(data):
        raise ArtifactError("Prefetch file size does not match header")
    if version not in {17, 23, 26, 30, 31}:
        raise DependencyUnavailable(f"Unsupported SCCA version: {version}")
    metrics = read("<I", 84)
    expected = {17: {152}, 23: {240}, 26: {304}, 30: {296, 304}, 31: {296}}
    if metrics not in expected[version]:
        raise DependencyUnavailable(f"Unknown SCCA {version} file information layout: {metrics}")
    run_offset = 144 if version == 17 else 152 if version == 23 else 200 if metrics == 296 else 208
    last_offset, time_count = (120, 1) if version == 17 else (128, 1 if version == 23 else 8)
    times = [filetime(read("<Q", last_offset + i * 8)) for i in range(time_count)]
    names_offset, names_size = read("<I", 100), read("<I", 104)
    references = [value for value in string(names_offset, names_size).split("\0") if value]
    volume_offset, volume_count, volume_size = read("<I", 108), read("<I", 112), read("<I", 116)
    volume_stride = 40 if version == 17 else 104 if version in {23, 26} else 96
    if volume_count * volume_stride > volume_size or volume_offset + volume_size > len(data):
        raise ArtifactError("Prefetch volume information outside file")
    volumes, directories = [], []
    for index in range(volume_count):
        base = volume_offset + index * volume_stride
        device = string(volume_offset + read("<I", base), read("<I", base + 4) * 2)
        volumes.append(
            {
                "name": device,
                "serial": f"{read('<I', base + 16):08X}",
                "created": filetime(read("<Q", base + 8)),
            }
        )
        directory_offset, directory_count = volume_offset + read("<I", base + 28), read("<I", base + 32)
        if directory_count > len(data) // 4:
            raise ArtifactError("Invalid Prefetch directory count")
        for _ in range(directory_count):
            length = read("<H", directory_offset)
            directories.append(string(directory_offset + 2, length * 2))
            directory_offset += 2 + (length + 1) * 2
    return {
        "ExecutableName": string(16, 60).split("\0")[0],
        "Hash": f"{read('<I', 76):08X}",
        "RunCount": read("<I", run_offset),
        "ExecutionTimes": [when for when in times if when],
        "FilesLoaded": references,
        "Directories": directories,
        "Volumes": volumes,
        "SourceFilename": path.name,
        "FormatVersion": version,
    }


def read_evtx(path):
    from engine.collectors.disk.artifacts import xml_records

    if path.stat().st_size < 4096:
        raise ArtifactError("Truncated EVTX file")
    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:
        raise DependencyUnavailable("Raw EVTX requires python-evtx") from exc
    rows = []
    with Evtx(str(path)) as evtx:
        header = evtx.get_file_header()
        # python-evtx's verify() only accepts 3.1, although its record reader also handles 3.2.
        if not (
            header.check_magic()
            and header.major_version() == 3
            and header.minor_version() in {1, 2}
            and header.header_chunk_size() == 4096
            and header.header_size() == 128
            and header.checksum() == header.calculate_checksum()
        ):
            raise ArtifactError("Invalid EVTX header/checksum")
        for chunk in evtx.chunks():
            if not chunk.verify():
                raise ArtifactError(f"Invalid EVTX chunk/checksum at {chunk.offset()}")
            for record in chunk.records():
                for _, raw in xml_records(record.xml()):
                    rows.append((f"bytes:{record.offset()}/record:{record.record_num()}", raw))
    return rows, []


def read_amcache(path):
    try:
        from dissect.regf import RegistryHive
        from dissect.regf.exceptions import RegistryKeyNotFoundError
    except ImportError as exc:
        raise DependencyUnavailable("Raw Amcache requires dissect.regf") from exc
    rows, warnings = [], []
    with path.open("rb") as stream:
        if stream.read(4) != b"regf":
            raise ArtifactError("Invalid Amcache registry hive signature")
        stream.seek(0)
        hive = RegistryHive(stream)
        for key_path in [r"Root\InventoryApplicationFile", r"Root\File"]:
            try:
                root = hive.open(key_path)
            except RegistryKeyNotFoundError:
                continue
            queue = [(root, 0)]
            while queue:
                key, depth = queue.pop()
                if depth > 4:
                    raise ArtifactError("Unexpected Amcache key nesting")
                values = {value.name: value.value for value in key.values()}
                path_value = values.get("LowerCaseLongPath") or values.get("15")
                if isinstance(path_value, str) and path_value:
                    raw = {
                        name: value.hex() if isinstance(value, bytes) else value
                        for name, value in values.items()
                    }
                    raw.update(
                        {
                            "FullPath": path_value,
                            "KeyPath": key.path,
                            "KeyLastWriteTimestamp": key.timestamp.isoformat(),
                            "Hive": path.name,
                        }
                    )
                    if "FileId" not in raw and "101" in raw:
                        raw["SHA1"] = raw["101"]
                    if "Size" not in raw and isinstance(raw.get("6"), int):
                        raw["Size"] = raw["6"]
                    rows.append((f"registry:{key.path}", raw))
                queue.extend((child, depth + 1) for child in key.subkeys())
        warnings.append("Amcache transaction logs and deleted registry cells were not replayed")
    return rows, warnings
