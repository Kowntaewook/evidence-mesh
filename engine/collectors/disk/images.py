"""Read-only raw evidence streams, partition discovery and derived NTFS artifacts."""

import hashlib
import json
import logging
import ntpath
import struct
import zlib
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from engine.collectors.disk.artifacts import DiskArtifactAdapter
from engine.ingestion.evidence import ArtifactError, DependencyUnavailable, EvidenceReader
from engine.runtime import workspace_root
from schemas.events import Source
from schemas.imports import ArtifactContext, ImportBatch, ParserRun, RunStatus

ARTIFACT_KINDS = ("mft", "usn", "prefetch", "evtx", "amcache")
MAX_ARTIFACT_SIZE = 2 * 1024**3
MAX_RECORDS = 4_000_000
MAX_DISCOVERED = 20_000
LOG = logging.getLogger("evidencemesh")


class RawEvidenceStream:
    """Container boundary: every implementation must expose a read-only stream."""

    @contextmanager
    def open(self, path):
        with Path(path).open("rb") as stream:
            yield stream


class E01EvidenceStream(RawEvidenceStream):
    @contextmanager
    def open(self, path):
        raise DependencyUnavailable(
            "E01 container reader is unavailable in this build. Export a verified raw image; "
            "E01 support remains PARTIAL and no E01 bytes are interpreted as raw NTFS."
        )
        yield  # pragma: no cover -- context manager protocol for future container readers


def evidence_stream(path):
    suffix = Path(path).suffix.casefold()
    if suffix in {".e01", ".ex01"}:
        return E01EvidenceStream().open(path)
    if suffix not in {".raw", ".img", ".dd"}:
        raise ArtifactError("Disk image must be .raw, .img, .dd or an explicitly supported container")
    return RawEvidenceStream().open(path)


def read_at(stream, offset, length, size):
    if offset < 0 or length < 0 or offset + length > size:
        raise ArtifactError("Disk structure extends outside the evidence image")
    stream.seek(offset)
    data = stream.read(length)
    if len(data) != length:
        raise ArtifactError("Truncated disk image")
    return data


def partitions(stream, size):
    """Superfloppy, four primary MBR entries, or CRC-checked primary GPT."""
    boot = read_at(stream, 0, 512, size)
    if boot[3:11] == b"NTFS    ":
        return [(0, size, "whole-volume")], []
    if boot[510:512] != b"\x55\xaa":
        raise ArtifactError("No valid NTFS boot sector or partition table")
    for sector_size in (512, 4096):
        if size < sector_size * 2:
            continue
        header = read_at(stream, sector_size, sector_size, size)
        if header[:8] != b"EFI PART":
            continue
        header_size, checksum = struct.unpack_from("<II", header, 12)
        if not 92 <= header_size <= sector_size:
            raise ArtifactError("Invalid GPT header length")
        checked = bytearray(header[:header_size])
        checked[16:20] = b"\0" * 4
        if zlib.crc32(checked) != checksum:
            raise ArtifactError("Invalid GPT header CRC32")
        current, backup, first, last = struct.unpack_from("<QQQQ", header, 24)
        entry_lba, count, width, array_crc = struct.unpack_from("<QIII", header, 72)
        if (
            current != 1
            or backup * sector_size >= size
            or not 2 <= first <= last < size // sector_size
            or not 1 <= count <= 4096
            or width < 128
            or width > 4096
            or width % 8
        ):
            raise ArtifactError("Invalid GPT geometry")
        entries = read_at(stream, entry_lba * sector_size, count * width, size)
        if zlib.crc32(entries) != array_crc:
            raise ArtifactError("Invalid GPT partition-array CRC32")
        result = []
        for index in range(count):
            entry = entries[index * width : (index + 1) * width]
            if entry[:16] == b"\0" * 16:
                continue
            start, end = struct.unpack_from("<QQ", entry, 32)
            if not first <= start <= end <= last:
                raise ArtifactError("GPT partition outside usable sectors")
            result.append((start * sector_size, (end - start + 1) * sector_size, f"gpt-{index + 1}"))
        return result, []
    result, warnings = [], []
    for index in range(4):
        entry = boot[446 + index * 16 : 462 + index * 16]
        kind = entry[4]
        start, length = struct.unpack_from("<II", entry, 8)
        if not kind:
            continue
        if kind == 0xEE:
            raise ArtifactError("Protective MBR has no valid primary GPT header")
        if kind in {5, 15, 0x85}:
            warnings.append("Extended MBR partitions are UNAVAILABLE; only primary partitions inspected")
            continue
        if not start or not length or (start + length) * 512 > size:
            raise ArtifactError("MBR partition extends outside image")
        result.append((start * 512, length * 512, f"mbr-{index + 1}"))
    return result, warnings


def volume_geometry(stream, offset, length, size):
    boot = read_at(stream, offset, 512, size)
    if boot[3:11] != b"NTFS    ":
        return None
    sector = struct.unpack_from("<H", boot, 11)[0]
    cluster_sectors = boot[13]
    sectors, mft_lcn = struct.unpack_from("<QQ", boot, 40)
    record_factor = struct.unpack_from("<b", boot, 64)[0]
    if sector not in {512, 1024, 2048, 4096} or cluster_sectors not in {1, 2, 4, 8, 16, 32, 64, 128}:
        raise DependencyUnavailable("Unsupported NTFS sector/cluster geometry")
    cluster = sector * cluster_sectors
    if not -12 <= record_factor <= 8 or not record_factor:
        raise DependencyUnavailable("Unsupported NTFS MFT record geometry")
    record_size = 1 << -record_factor if record_factor < 0 else record_factor * cluster
    if record_size not in {1024, 2048, 4096}:
        raise DependencyUnavailable("Unsupported NTFS MFT record size")
    if (
        not sectors
        or sectors * sector > length
        or mft_lcn * cluster + record_size > length
        or boot[510:512] != b"\x55\xaa"
    ):
        raise ArtifactError("Invalid NTFS volume bounds")
    return {"sector_size": sector, "cluster_size": cluster, "record_size": record_size}


def record_paths(record, mft):
    """Resolve allocated parent identities with a depth bound, never reparse targets."""
    from dissect.ntfs.util import segment_reference

    def ascend(current, seen):
        if current.segment == 5:
            return [""]
        if current.segment in seen or len(seen) >= 64 or not int(current.header.Flags) & 1:
            return []
        result = []
        for name in current.attributes.FILE_NAME:
            if int(name.flags) == 2:
                continue
            parent_ref = name.attr.ParentDirectory
            parent = mft.get(segment_reference(parent_ref))
            if parent.header.SequenceNumber != parent_ref.SequenceNumber:
                continue
            for prefix in ascend(parent, seen | {current.segment}):
                result.append(prefix + "\\" + name.file_name)
                if len(result) >= 64:
                    return result
        return result

    return ascend(record, set())


def discover_artifacts(ntfs):
    size = ntfs.mft.get(0).size()
    records = size // ntfs._record_size
    if records > MAX_RECORDS:
        raise ArtifactError(f"NTFS discovery exceeds {MAX_RECORDS} MFT records")
    result = [{"kind": "mft", "record": 0, "stream": "", "path": "\\$MFT", "size": size}]
    warnings = []
    failures = 0
    for record in ntfs.mft.segments(end=max(0, records - 1)):
        if record.segment == 0 or record.is_dir() or not int(record.header.Flags) & 1:
            continue
        try:
            # Filter names first so paths are resolved only for artifact candidates.
            names = [name.casefold() for name in record.filenames(ignore_dos=True)]
            if not any(
                name in {"$usnjrnl", "amcache.hve"} or name.endswith((".pf", ".evtx")) for name in names
            ):
                continue
            for path in record_paths(record, ntfs.mft):
                lower, stream, kind = path.casefold(), "", None
                if lower == "\\$extend\\$usnjrnl":
                    kind, stream = "usn", "$J"
                elif lower.startswith("\\windows\\prefetch\\") and lower.endswith(".pf"):
                    kind = "prefetch"
                elif lower.startswith("\\windows\\system32\\winevt\\logs\\") and lower.endswith(".evtx"):
                    kind = "evtx"
                elif lower == "\\windows\\appcompat\\programs\\amcache.hve":
                    kind = "amcache"
                if kind:
                    result.append(
                        {
                            "kind": kind,
                            "record": record.segment,
                            "stream": stream,
                            "path": path,
                            "size": record.size(stream),
                        }
                    )
                    break
        except Exception:
            failures += 1
        if len(result) > MAX_DISCOVERED:
            raise ArtifactError(f"NTFS discovery exceeds {MAX_DISCOVERED} artifacts")
    if failures:
        warnings.append(f"Could not resolve {failures} candidate MFT records; discovery is partial")
    return result, warnings


class DiskImageAdapter:
    def __init__(self, context: ArtifactContext, workspace: Path | None = None):
        self.context = context
        self.workspace = Path(workspace) if workspace else workspace_root()

    def volumes(self, stream, size):
        from dissect.ntfs import NTFS
        from dissect.util.stream import RangeStream

        candidates, warnings = partitions(stream, size)
        volumes = []
        for offset, length, partition in candidates:
            volume = {
                "id": f"offset-{offset}",
                "partition": partition,
                "offset": offset,
                "size": length,
                "artifacts": [],
            }
            try:
                geometry = volume_geometry(stream, offset, length, size)
                if geometry is None:
                    volume.update(
                        filesystem="UNAVAILABLE", status="UNAVAILABLE", error="Partition is not NTFS"
                    )
                else:
                    ntfs = NTFS(RangeStream(stream, offset, length))
                    artifacts, partial = discover_artifacts(ntfs)
                    volume.update(
                        geometry,
                        filesystem="NTFS",
                        serial=f"{ntfs.serial:016X}",
                        status="PARTIAL" if partial else "SUCCESS",
                        artifacts=artifacts,
                        warnings=partial,
                    )
            except DependencyUnavailable as exc:
                volume.update(filesystem="NTFS", status="UNAVAILABLE", error=str(exc))
            except Exception as exc:
                volume.update(filesystem="NTFS", status="FAILED", error=f"{type(exc).__name__}: {exc}")
            volumes.append(volume)
        return volumes, warnings

    def inspect(self, path):
        path = Path(path).resolve()
        with evidence_stream(path) as stream:
            volumes, warnings = self.volumes(stream, path.stat().st_size)
        return {"path": str(path), "volumes": volumes, "warnings": warnings, "read_only": True}

    def load_file(self, path, kinds=None, volume_ids=None):
        from dissect.ntfs import NTFS
        from dissect.util.stream import RangeStream

        kinds = set(ARTIFACT_KINDS if kinds is None else kinds)
        if not kinds or kinds - set(ARTIFACT_KINDS):
            raise ArtifactError("Select supported disk artifact kinds")
        path = Path(path).resolve()
        batch = ImportBatch()
        run = ParserRun(parser="NTFSImageAdapter", source=Source.DISK, status=RunStatus.FAILED)
        batch.runs.append(run)
        try:
            before = path.stat()
            # Check container support before a potentially lengthy image hash.
            with evidence_stream(path) as stream:
                reader = EvidenceReader(path, Source.DISK, "disk_image", self.context, run.parser)
                run.artifact = reader.artifact
                volumes, warnings = self.volumes(stream, before.st_size)
                run.warnings.extend(warnings)
                selected = [v for v in volumes if volume_ids is None or v["id"] in volume_ids]
                if volume_ids is not None and set(volume_ids) - {v["id"] for v in volumes}:
                    raise ArtifactError("Selected volume no longer exists in image")
                destination = self.workspace / "derived" / "ntfs" / reader.artifact.sha256 / str(uuid4())
                destination.mkdir(parents=True, exist_ok=False)
                manifest = {
                    "original": reader.artifact.model_dump(mode="json"),
                    "volumes": selected,
                    "artifacts": [],
                }
                extracted = 0
                for volume in selected:
                    if volume["status"] not in {"SUCCESS", "PARTIAL"}:
                        run.warnings.append(f"{volume['id']}: {volume.get('error', volume['status'])}")
                        continue
                    ntfs = NTFS(RangeStream(stream, volume["offset"], volume["size"]))
                    context = self.context.model_copy(
                        update={
                            "volume_id": self.context.volume_id or f"ntfs:{volume['serial']}",
                            "extracted_at": datetime.now(UTC),
                        }
                    )
                    adapter = DiskArtifactAdapter(context)
                    for item in volume["artifacts"]:
                        if item["kind"] not in kinds:
                            continue
                        target = destination / volume["id"] / f"{item['kind']}-{item['record']}.bin"
                        entry = {
                            **item,
                            "volume_id": volume["id"],
                            "derived": str(target),
                            "status": "FAILED",
                        }
                        manifest["artifacts"].append(entry)
                        try:
                            if item["size"] > MAX_ARTIFACT_SIZE:
                                raise ArtifactError("Artifact exceeds the 2 GiB extraction bound")
                            target.parent.mkdir(parents=True, exist_ok=True)
                            digest, copied = hashlib.sha256(), 0
                            source = ntfs.mft.get(item["record"]).open(item["stream"])
                            with source, target.open("xb") as output:
                                while chunk := source.read(1024 * 1024):
                                    copied += len(chunk)
                                    if copied > item["size"]:
                                        raise ArtifactError("NTFS stream exceeds declared length")
                                    output.write(chunk)
                                    digest.update(chunk)
                            if copied != item["size"]:
                                raise ArtifactError("Truncated NTFS stream")
                            result = adapter.load_file(target, item["kind"])
                            locator = (
                                f"volume:{volume['offset']}/mft:{item['record']}/stream:{item['stream']}"
                            )
                            provenance = reader.provenance(
                                locator, {**item, "volume_serial": volume["serial"]}, extracted
                            )
                            provenance.extraction_timestamp = context.extracted_at
                            for event in result.events:
                                identity = f"{reader.artifact.sha256}:{volume['offset']}"
                                event.event_id += "-" + hashlib.sha256(identity.encode()).hexdigest()[:12]
                                if event.file:
                                    event.file.volume_id = event.file.volume_id or context.volume_id
                                    if item["kind"] == "prefetch":
                                        event.file.path = (
                                            ntpath.join(context.mount_point, item["path"].lstrip("\\"))
                                            if context.mount_point
                                            else item["path"]
                                        )
                                        event.file.name = ntpath.basename(item["path"])
                                event.provenance.append(provenance)
                                event.metadata.update(
                                    original_image_sha256=reader.artifact.sha256,
                                    original_volume=volume["id"],
                                    original_ntfs_path=item["path"],
                                    derived_path=str(target),
                                )
                            if item["kind"] == "mft":
                                adapter.mft_events = result.events
                            batch.events.extend(result.events)
                            batch.runs.extend(result.runs)
                            entry.update(
                                sha256=digest.hexdigest(), size=copied, status=result.runs[0].status.value
                            )
                            extracted += 1
                        except Exception as exc:
                            entry["error"] = f"{type(exc).__name__}: {exc}"
                            batch.runs.append(
                                ParserRun(
                                    parser=f"{item['kind'].upper()}Extraction",
                                    source=Source.DISK,
                                    status=RunStatus.FAILED,
                                    artifact=reader.artifact,
                                    error=entry["error"],
                                    finished_at=datetime.now(UTC),
                                )
                            )
                after = path.stat()
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    batch.events.clear()
                    raise ArtifactError("Original image changed during extraction; events rejected")
                (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                run.row_count, run.event_count = extracted, len(batch.events)
                if not extracted:
                    raise ArtifactError(
                        "No selected artifacts could be extracted from a supported NTFS volume"
                    )
                run.status = RunStatus.SUCCESS
        except DependencyUnavailable as exc:
            run.status, run.error = RunStatus.UNAVAILABLE, str(exc)
        except Exception as exc:
            run.error = f"{type(exc).__name__}: {exc}"
        run.finished_at = datetime.now(UTC)
        LOG.info(
            "Disk image extraction status=%s artifacts=%d events=%d",
            run.status.value,
            run.row_count,
            len(batch.events),
        )
        return batch
