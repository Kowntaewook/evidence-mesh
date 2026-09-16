"""Actual inert NTFS byte images: real Dissect reads, no NTFS parser mocks."""

import hashlib
import json
import struct
import zlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from engine.collectors.disk.images import DiskImageAdapter
from engine.ingestion.evidence import ArtifactError, DependencyUnavailable
from schemas.imports import ArtifactContext, RunStatus

FIXTURES = Path(__file__).parent / "fixtures" / "disk"


def resident(kind, content, name=""):
    label = name.encode("utf-16-le")
    offset = (24 + len(label) + 7) // 8 * 8
    size = (offset + len(content) + 7) // 8 * 8
    data = bytearray(size)
    struct.pack_into(
        "<IIBBHHHIH", data, 0, kind, size, 0, len(name), 24 if name else 0, 0, 0, len(content), offset
    )
    data[24 : 24 + len(label)] = label
    data[offset : offset + len(content)] = content
    return bytes(data)


def mft_record(index, name, parent=5, directory=False, content=None, stream="", attributes=()):
    filename = bytearray(66)
    struct.pack_into("<Q", filename, 0, parent | 1 << 48)
    for offset in (8, 16, 24, 32):
        struct.pack_into("<Q", filename, offset, 134024880000000000)
    if content is not None:
        struct.pack_into("<QQ", filename, 40, len(content), len(content))
    struct.pack_into("<BB", filename, 64, len(name), 1)
    filename.extend(name.encode("utf-16-le"))
    attrs = resident(0x30, filename) + b"".join(attributes)
    if content is not None:
        attrs += resident(0x80, content, stream)
    if directory:
        root = bytearray(48)
        struct.pack_into("<III", root, 0, 0x30, 1, 4096)
        root[12] = 1
        struct.pack_into("<III", root, 16, 16, 32, 32)
        struct.pack_into("<HHI", root, 40, 16, 0, 2)
        attrs += resident(0x90, root, "$I30")
    data = bytearray(1024)
    data[:4] = b"FILE"
    struct.pack_into("<HH", data, 4, 48, 3)
    struct.pack_into("<HHHHII", data, 16, 1, 1, 56, 3 if directory else 1, 56 + len(attrs) + 8, 1024)
    struct.pack_into("<I", data, 44, index)
    data[56 : 56 + len(attrs)] = attrs
    struct.pack_into("<I", data, 56 + len(attrs), 0xFFFFFFFF)
    assert len(data) == 1024 and 56 + len(attrs) + 8 < 1024
    data[48:54] = b"\xaa\xaa" + data[510:512] + data[1022:1024]
    data[510:512] = data[1022:1024] = b"\xaa\xaa"
    return bytes(data)


def ntfs_volume():
    size, cluster, mft_start, records = 128 * 1024, 4096, 4, 64
    volume = bytearray(size)
    volume[:11] = b"\xeb\x52\x90NTFS    "
    struct.pack_into("<HB", volume, 11, 512, cluster // 512)
    struct.pack_into("<QQQ", volume, 40, size // 512, mft_start, 2)
    struct.pack_into("<b", volume, 64, -10)
    struct.pack_into("<b", volume, 68, -12)
    struct.pack_into("<Q", volume, 72, 0x12345678AABBCCDD)
    volume[510:512] = b"\x55\xaa"
    data = bytearray(72)
    struct.pack_into("<IIB", data, 0, 0x80, 72, 1)
    struct.pack_into("<QQH", data, 16, 0, records * 1024 // cluster - 1, 64)
    struct.pack_into("<QQQ", data, 40, records * 1024, records * 1024, records * 1024)
    data[64:68] = bytes([0x11, records * 1024 // cluster, mft_start, 0])
    entries = {
        0: mft_record(0, "$MFT", attributes=[data]),
        3: mft_record(3, "$Volume"),
        5: mft_record(5, ".", directory=True),
        11: mft_record(11, "$Extend", directory=True),
        16: mft_record(16, "Windows", directory=True),
        17: mft_record(17, "Prefetch", 16, directory=True),
        18: mft_record(18, "System32", 16, directory=True),
        19: mft_record(19, "winevt", 18, directory=True),
        20: mft_record(20, "Logs", 19, directory=True),
        21: mft_record(21, "appcompat", 16, directory=True),
        22: mft_record(22, "Programs", 21, directory=True),
        30: mft_record(30, "POWERSHELL.PF", 17, content=(FIXTURES / "sample-v30.pf").read_bytes()),
        31: mft_record(31, "$UsnJrnl", 11, content=(FIXTURES / "usn-v2.bin").read_bytes(), stream="$J"),
        # Discovery succeeds but format parsers must reject intentionally corrupt content.
        32: mft_record(32, "Application.evtx", 20, content=b"corrupt EVTX"),
        33: mft_record(33, "Amcache.hve", 22, content=b"corrupt registry"),
        42: mft_record(42, "a.ps1", content=b"inert text\n"),
    }
    for index, record in entries.items():
        offset = mft_start * cluster + index * 1024
        volume[offset : offset + 1024] = record
    return bytes(volume)


def image_bytes(layout):
    volume = ntfs_volume()
    if layout == "volume":
        return volume, 0
    start = 2048
    sectors = len(volume) // 512
    image = bytearray((start + sectors + 34) * 512)
    image[start * 512 : (start + sectors) * 512] = volume
    image[510:512] = b"\x55\xaa"
    image[450] = 7 if layout == "mbr" else 0xEE
    struct.pack_into("<II", image, 454, start if layout == "mbr" else 1, sectors)
    if layout == "gpt":
        entries = bytearray(512)
        entries[:16], entries[16:32] = b"T" * 16, b"U" * 16
        struct.pack_into("<QQ", entries, 32, start, start + sectors - 1)
        image[1024:1536] = entries
        header = bytearray(512)
        struct.pack_into(
            "<8sIIIIQQQQ",
            header,
            0,
            b"EFI PART",
            0x10000,
            92,
            0,
            0,
            1,
            len(image) // 512 - 1,
            34,
            start + sectors - 1,
        )
        struct.pack_into("<QIII", header, 72, 2, 4, 128, zlib.crc32(entries))
        struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
        image[512:1024] = header
    return bytes(image), start * 512


@pytest.fixture
def adapter(tmp_path):
    return DiskImageAdapter(
        ArtifactContext(acquisition_id="whole-disk", extracted_at=datetime.now(UTC), mount_point="C:\\"),
        tmp_path / "workspace",
    )


@pytest.mark.parametrize("layout,extension", [("volume", ".raw"), ("mbr", ".img"), ("gpt", ".dd")])
def test_real_ntfs_discovery_extraction_lineage_and_read_only(tmp_path, adapter, layout, extension):
    data, offset = image_bytes(layout)
    image = tmp_path / ("evidence" + extension)
    image.write_bytes(data)
    before = image.stat()
    digest = hashlib.sha256(data).hexdigest()
    inspected = adapter.inspect(image)
    assert inspected["read_only"] is True
    volume = inspected["volumes"][0]
    assert volume["status"] == "SUCCESS", volume
    assert volume["offset"] == offset and volume["serial"] == "12345678AABBCCDD"
    assert {item["kind"] for item in volume["artifacts"]} == {"mft", "usn", "prefetch", "evtx", "amcache"}
    result = adapter.load_file(image, kinds=["mft", "usn", "prefetch"])
    assert all(run.status == RunStatus.SUCCESS for run in result.runs), [run.error for run in result.runs]
    assert {event.artifact_type for event in result.events} == {"$MFT", "$UsnJrnl", "Prefetch"}
    for event in result.events:
        assert event.metadata["original_image_sha256"] == digest
        assert event.provenance[-1].source_artifact.sha256 == digest
        assert event.provenance[-1].raw_reference.locator.startswith(f"volume:{offset}/mft:")
        assert event.source_artifact.path != str(image)
        assert event.file.volume_id == "ntfs:12345678AABBCCDD"
    manifests = list(adapter.workspace.rglob("manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text())
    assert len(manifest["artifacts"]) == 3
    for artifact in manifest["artifacts"]:
        assert hashlib.sha256(Path(artifact["derived"]).read_bytes()).hexdigest() == artifact["sha256"]
    assert hashlib.sha256(image.read_bytes()).hexdigest() == digest
    assert image.stat().st_mtime_ns == before.st_mtime_ns


def test_disk_partial_artifact_failure_and_selection(tmp_path, adapter):
    image = tmp_path / "disk.img"
    image.write_bytes(ntfs_volume())
    result = adapter.load_file(image)
    assert result.runs[0].status == RunStatus.SUCCESS
    assert result.events
    assert [run.status for run in result.runs].count(RunStatus.FAILED) == 2
    assert len(adapter.load_file(image, ["prefetch"], ["offset-0"]).events) == 1
    rejected = adapter.load_file(image, volume_ids=["offset-999"])
    assert rejected.runs[0].status == RunStatus.FAILED and not rejected.events


def test_e01_is_explicitly_unavailable_and_bad_gpt_is_rejected(tmp_path, adapter):
    image = tmp_path / "container.E01"
    image.write_bytes(ntfs_volume())
    with pytest.raises(DependencyUnavailable, match="E01"):
        adapter.inspect(image)
    assert adapter.load_file(image).runs[0].status == RunStatus.UNAVAILABLE
    image = tmp_path / "bad.dd"
    data = bytearray(image_bytes("gpt")[0])
    data[1024] ^= 1
    image.write_bytes(data)
    with pytest.raises(ArtifactError, match="CRC32"):
        adapter.inspect(image)
    assert adapter.load_file(image).runs[0].status == RunStatus.FAILED


def test_disk_image_api_is_case_scoped_and_persists_parser_runs(client, tmp_path):
    image = tmp_path / "case.img"
    image.write_bytes(ntfs_volume())
    case = client.post("/cases", json={"name": "Disk image"}).json()["case_id"]
    body = {
        "path": str(image),
        "context": {"acquisition_id": "api-image", "extracted_at": "2026-09-16T00:00:00Z"},
        "artifacts": ["prefetch"],
    }
    base = f"/cases/{case}/disk-images"
    assert client.post("/cases/missing/disk-images/inspect", json=body).status_code == 404
    inspected = client.post(base + "/inspect", json=body)
    assert inspected.status_code == 200 and inspected.json()["volumes"][0]["filesystem"] == "NTFS"
    imported = client.post(base + "/import", json=body)
    assert imported.status_code == 200 and imported.json()["status"] == "SUCCESS", imported.text
    assert imported.json()["imported"] == 1
    assert len(client.get(f"/cases/{case}/parser-runs").json()) == 2
