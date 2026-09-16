"""Generated inert format fixtures; no dependency on downloaded private evidence."""

import hashlib
import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from engine.collectors.disk.artifacts import DiskArtifactAdapter
from engine.collectors.disk.prefetch_compression import decompress_mam
from engine.collectors.disk.raw import read_prefetch, read_usn
from engine.ingestion.evidence import ArtifactError, DependencyUnavailable
from schemas.imports import ArtifactContext, RunStatus

FIXTURES = Path(__file__).parent / "fixtures" / "disk"
STAMP = 134024880000000000


def prefetch_bytes(version):
    header_size = {17: 152, 23: 240, 26: 304, 30: 296, 31: 296}[version]
    data = bytearray(header_size)
    struct.pack_into("<I4s", data, 0, version, b"SCCA")
    data[16:32] = "TEST.EXE".encode("utf-16-le")
    struct.pack_into("<I", data, 76, 0x10203040)
    struct.pack_into("<I", data, 84, header_size)
    time_offset, count = (120, 1) if version == 17 else (128, 1 if version == 23 else 8)
    for index in range(count):
        struct.pack_into("<Q", data, time_offset + index * 8, STAMP + index * 10000000)
    struct.pack_into("<I", data, {17: 144, 23: 152, 26: 208, 30: 200, 31: 200}[version], 9)
    names = "C:\\Temp\\test.exe\0C:\\Windows\\a.dll\0".encode("utf-16-le")
    struct.pack_into("<II", data, 100, len(data), len(names))
    data.extend(names)
    stride = 40 if version == 17 else 104 if version in {23, 26} else 96
    device = "\\Device\\HarddiskVolume1".encode("utf-16-le")
    directory = "C:\\Temp".encode("utf-16-le")
    volume = bytearray(stride)
    struct.pack_into("<IIQI", volume, 0, stride, len(device) // 2, STAMP, 0xAABBCCDD)
    struct.pack_into("<II", volume, 28, stride + len(device), 1)
    volume.extend(device + struct.pack("<H", len(directory) // 2) + directory + b"\0\0")
    struct.pack_into("<III", data, 108, len(data), 1, len(volume))
    data.extend(volume)
    struct.pack_into("<I", data, 12, len(data))
    return bytes(data)


def mam_literals(data):
    # Canonical complete 512-symbol, nine-bit Huffman alphabet. Literal-only
    # encoding exercises the real decoder with a reproducible valid stream.
    return mam_symbols(data, len(data))


def mam_symbols(symbols, size):
    bits = "".join(f"{value:09b}" for value in symbols)
    bits += "0" * ((-len(bits)) % 16)
    payload = b"".join(struct.pack("<H", int(bits[i : i + 16], 2)) for i in range(0, len(bits), 16))
    return b"MAM\x04" + struct.pack("<I", size) + b"\x99" * 256 + payload + b"\0" * 4


@pytest.mark.parametrize("version", [17, 23, 26, 30, 31])
@pytest.mark.parametrize("compressed", [False, True])
def test_prefetch_versions_and_mam_keep_all_fields(tmp_path, version, compressed):
    original = prefetch_bytes(version)
    payload = mam_literals(original) if compressed else original
    path = tmp_path / "test.pf"
    path.write_bytes(payload)
    before = hashlib.sha256(payload).hexdigest()
    if compressed:
        assert decompress_mam(payload) == original
    result = read_prefetch(path)
    assert result["FormatVersion"] == version
    assert result["ExecutableName"] == "TEST.EXE" and result["RunCount"] == 9
    assert len(result["ExecutionTimes"]) == (1 if version in {17, 23} else 8)
    assert result["FilesLoaded"] == ["C:\\Temp\\test.exe", "C:\\Windows\\a.dll"]
    assert result["Directories"] == ["C:\\Temp"]
    assert result["Volumes"][0]["serial"] == "AABBCCDD"
    assert result["Volumes"][0]["created"] == result["ExecutionTimes"][0]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


def test_mam_match_and_bad_stream_bounds():
    # Independent public decoder agreement is checked on the repository's
    # synthetic payload; a repeated literal followed by a match exercises LZ.
    from dissect.util.compression.lzxpress_huffman import decompress

    data = prefetch_bytes(30)
    encoded = mam_literals(data)
    assert decompress(encoded[8:]).startswith(data)
    expected = data + b"\0" * 3
    assert decompress_mam(mam_symbols([*data, 256], len(expected))) == expected
    with pytest.raises(ArtifactError, match="bounds"):
        decompress_mam(mam_symbols([*data, 256], len(data) + 2))
    for invalid in (b"MAM", b"MAM\x04" + struct.pack("<I", 2**31), encoded[:-30], encoded[:100]):
        with pytest.raises(ArtifactError):
            decompress_mam(invalid)
    with pytest.raises(DependencyUnavailable, match="variant"):
        decompress_mam(b"MAM\x84" + encoded[4:])


def usn_record(version, reference=(3 << 48) + 42, parent=(1 << 48) + 5):
    if version == 2:
        return (FIXTURES / "usn-v2.bin").read_bytes()
    data = bytearray(80 if version == 4 else 96)
    struct.pack_into("<IHH", data, 0, len(data), version, 0)
    data[8:24], data[24:40] = reference.to_bytes(16, "little"), parent.to_bytes(16, "little")
    struct.pack_into("<q", data, 40, 91821)
    if version == 3:
        struct.pack_into("<QIIIIHH", data, 48, STAMP, 0x100, 0, 0, 0, 10, 76)
        data[76:86] = "a.ps1".encode("utf-16-le")
    else:
        struct.pack_into("<IIIHHqq", data, 48, 1, 0, 2, 1, 16, 4096, 8192)
    return bytes(data)


@pytest.mark.parametrize("version", [2, 3, 4])
def test_usn_native_versions_and_immutable_source(tmp_path, version):
    path = tmp_path / "journal.bin"
    data = usn_record(version)
    path.write_bytes(data)
    rows, _ = read_usn(path)
    assert len(rows) == 1 and rows[0][1]["MajorVersion"] == version
    context = ArtifactContext(acquisition_id="disk-native", extracted_at=datetime.now(UTC), volume_id="vol")
    batch = DiskArtifactAdapter(context).load_file(path, "usn")
    assert batch.runs[0].status == RunStatus.SUCCESS, batch.runs[0].error
    event = batch.events[0]
    assert event.journal.version == version and event.journal.usn == 91821
    assert event.file.record_number == 42 and event.file.sequence_number == 3
    if version == 4:
        assert event.type == "usn_range_change" and event.timestamp_semantics == "extraction_time"
        assert event.file.name is None and event.file.path is None
        assert event.journal.extents == [{"offset": 4096, "length": 8192}]
        assert event.journal.remaining_extents == 2
    else:
        assert event.type == "file_created" and event.file.name == "a.ps1"
    assert path.read_bytes() == data


@pytest.mark.parametrize("version", [3, 4])
def test_usn_128_bit_identity_is_not_truncated(tmp_path, version):
    reference = (1 << 100) + 42
    path = tmp_path / "journal.bin"
    path.write_bytes(usn_record(version, reference=reference))
    row = read_usn(path)[0][0][1]
    assert row["FileReference128"] == f"0x{reference:032x}"
    assert "EntryNumber" not in row and "SequenceNumber" not in row
    context = ArtifactContext(acquisition_id="opaque-id", extracted_at=datetime.now(UTC))
    batch = DiskArtifactAdapter(context).load_file(path, "usn")
    assert batch.runs[0].status == RunStatus.SUCCESS, batch.runs[0].error
    assert batch.events[0].file.file_id128 == f"0x{reference:032x}"
    assert batch.events[0].file.record_number is None


def test_usn_sparse_padding_malformed_and_unknown_layouts(tmp_path):
    path = tmp_path / "journal.bin"
    path.write_bytes(b"\0" * 65536 + usn_record(3) + b"\0" * 24 + usn_record(4))
    rows, _ = read_usn(path)
    assert [row[1]["MajorVersion"] for row in rows] == [3, 4]
    for offset, fmt, value, error in [
        (4, "<H", 5, DependencyUnavailable),
        (6, "<H", 1, DependencyUnavailable),
        (0, "<I", 12, ArtifactError),
        (74, "<H", 1000, ArtifactError),
    ]:
        data = bytearray(usn_record(3))
        struct.pack_into(fmt, data, offset, value)
        path.write_bytes(data)
        with pytest.raises(error):
            read_usn(path)
    data = bytearray(usn_record(4))
    struct.pack_into("<H", data, 62, 24)
    path.write_bytes(data)
    with pytest.raises(DependencyUnavailable, match="extent size"):
        read_usn(path)
