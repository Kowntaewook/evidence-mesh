import hashlib
import json
import struct
from pathlib import Path

import pytest

from engine.collectors.disk.artifacts import DiskArtifactAdapter
from schemas.events import Event
from schemas.imports import ArtifactContext, RunStatus

FIXTURES = Path(__file__).parent / "fixtures" / "disk"
KINDS = ["mft", "usn", "prefetch", "evtx", "amcache"]


@pytest.fixture
def adapter():
    return DiskArtifactAdapter(
        ArtifactContext(
            acquisition_id="disk-capture-1",
            extracted_at="2026-09-16T09:35:00Z",
            hostname="workstation-01",
            volume_id="volume-C",
            mount_point="C:\\",
        )
    )


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("suffix", ["csv", "json"])
def test_disk_normal_exports_and_integrity(adapter, kind, suffix):
    path = FIXTURES / f"{kind}.{suffix}"
    original = path.read_bytes()
    batch = adapter.load_file(path, kind)
    assert batch.runs[0].status == RunStatus.SUCCESS, batch.runs[0].error
    assert batch.runs[0].row_count == 1
    assert len(batch.events) == (2 if kind == "prefetch" else 1)
    for event in batch.events:
        assert event.source == "disk" and event.provenance[0].source == "disk"
        assert event.provenance[0].memory_image_id is None
        assert event.source_artifact.sha256 == hashlib.sha256(original).hexdigest()
        assert event.source_artifact.size == len(original)
        assert event.source_artifact.imported_at
        assert Event.model_validate_json(event.model_dump_json()) == event
    assert path.read_bytes() == original


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("content", ['[{"nonsense": 1}]', "{broken", '"a",b\n"unterminated,b'])
def test_disk_malformed_records(adapter, tmp_path, kind, content):
    path = tmp_path / ("bad.csv" if content.startswith('"') else "bad.json")
    path.write_text(content)
    batch = adapter.load_file(path, kind)
    assert batch.runs[0].status == RunStatus.FAILED
    assert batch.runs[0].error and batch.events == []


@pytest.mark.parametrize(
    "kind,minimal",
    [
        ("mft", {"EntryNumber": 1, "FileName": "a.txt"}),
        (
            "usn",
            {
                "EntryNumber": 1,
                "Name": "a.txt",
                "USN": 1,
                "Timestamp": "2026-09-16T00:00:00Z",
                "Reason": "CLOSE",
            },
        ),
        ("prefetch", {"ExecutableName": "A.EXE"}),
        ("evtx", {"Provider": "Example", "EventId": 42, "Timestamp": "2026-09-16T00:00:00Z"}),
        ("amcache", {"FullPath": "C:\\a.exe"}),
    ],
)
def test_disk_optional_fields(adapter, tmp_path, kind, minimal):
    path = tmp_path / "minimal.json"
    path.write_text(json.dumps([minimal]))
    batch = adapter.load_file(path, kind)
    assert batch.runs[0].status == RunStatus.SUCCESS, batch.runs[0].error
    assert len(batch.events) == 1
    if kind in {"mft", "prefetch", "amcache"}:
        assert batch.events[0].timestamp_semantics == "extraction_time"


def test_usn_mft_sequence_volume_name_and_provenance(adapter):
    mft = adapter.load_file(FIXTURES / "mft.csv", "mft").events
    adapter.mft_events = mft
    usn = adapter.load_file(FIXTURES / "usn.csv", "usn").events[0]
    assert usn.file.path == mft[0].file.path
    assert usn.file.sequence_number == 3 and usn.journal.usn == 91821
    assert set(usn.journal.reasons) == {"FILE_CREATE", "DATA_EXTEND", "CLOSE"}
    assert len(usn.provenance) == 2
    mft[0].file.sequence_number = 4
    mismatch = adapter.load_file(FIXTURES / "usn.csv", "usn").events[0]
    assert mismatch.file.path is None and len(mismatch.provenance) == 1
    mft[0].file.sequence_number = 3
    mft[0].file.volume_id = "different-volume"
    assert adapter.load_file(FIXTURES / "usn.csv", "usn").events[0].file.path is None


def test_mft_parent_path_resolution_rejects_reused_parent(adapter, tmp_path):
    rows = [
        {"EntryNumber": 5, "SequenceNumber": 1, "FileName": "."},
        {
            "EntryNumber": 10,
            "SequenceNumber": 2,
            "ParentEntryNumber": 5,
            "ParentSequenceNumber": 1,
            "FileName": "Temp",
        },
        {
            "EntryNumber": 12,
            "SequenceNumber": 1,
            "ParentEntryNumber": 10,
            "ParentSequenceNumber": 2,
            "FileName": "a.ps1",
        },
        {
            "EntryNumber": 13,
            "SequenceNumber": 1,
            "ParentEntryNumber": 10,
            "ParentSequenceNumber": 1,
            "FileName": "wrong.ps1",
        },
    ]
    path = tmp_path / "tree.json"
    path.write_text(json.dumps(rows))
    events = adapter.load_file(path, "mft").events
    assert events[2].file.path == "C:\\Temp\\a.ps1"
    assert events[3].file.path is None
    assert len(events[2].provenance) == 3


def test_timezone_is_explicit(adapter, tmp_path):
    rows = json.loads((FIXTURES / "mft.json").read_text())
    rows[0]["Created0x10"] = "2026-09-16 09:31:25"
    path = tmp_path / "time.json"
    path.write_text(json.dumps(rows))
    assert adapter.load_file(path, "mft").runs[0].status == RunStatus.FAILED
    adapter.context.timezone = "UTC"
    assert adapter.load_file(path, "mft").runs[0].status == RunStatus.SUCCESS


def test_xml_evtx_and_process_provider_semantics(adapter, tmp_path):
    event = adapter.load_file(FIXTURES / "event.xml", "evtx").events[0]
    assert event.type == "network_connection"
    assert event.process.pid == 4120 and event.network.dst_port == 443
    assert event.event_log.record_id == 124
    assert "OriginalXML" in event.raw
    path = tmp_path / "security.json"
    path.write_text(
        json.dumps(
            [
                {
                    "Provider": "Microsoft-Windows-Security-Auditing",
                    "EventId": 4688,
                    "Timestamp": "2026-09-16T09:31:25Z",
                    "EventData": {
                        "NewProcessId": "0x1018",
                        "ProcessId": "0xce4",
                        "NewProcessName": "C:\\Windows\\powershell.exe",
                        "CommandLine": "powershell.exe",
                    },
                }
            ]
        )
    )
    event = adapter.load_file(path, "evtx").events[0]
    assert event.process.pid == 4120 and event.process.ppid == 3300
    assert event.type == "process_start"
    path.write_text(
        json.dumps([{"Provider": "Unrelated provider", "EventId": 1, "Timestamp": "2026-09-16T00:00:00Z"}])
    )
    assert adapter.load_file(path, "evtx").events[0].type == "event_log"


@pytest.mark.parametrize(
    "kind,filename", [("mft", "mft-record.bin"), ("usn", "usn-v2.bin"), ("prefetch", "sample-v30.pf")]
)
def test_binary_disk_metadata(adapter, kind, filename):
    path = FIXTURES / filename
    before = path.read_bytes()
    result = adapter.load_file(path, kind)
    assert result.runs[0].status == RunStatus.SUCCESS, result.runs[0].error
    assert len(result.events) == 1
    event = result.events[0]
    assert event.raw_reference.locator.startswith("bytes:")
    if kind == "mft":
        assert event.file.name == "a.ps1" and event.file.sequence_number == 3
        assert len(event.file.si_timestamps) == 4 and len(event.file.fn_timestamps) == 4
    elif kind == "usn":
        assert event.journal.usn == 91821 and event.file.record_number == 42
        assert event.type == "file_created"
    else:
        assert event.prefetch.executable == "POWERSHELL.EXE" and event.prefetch.run_count == 3
        assert event.file.references[0].endswith("a.ps1")
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "kind,suffix",
    [("mft", ".bin"), ("usn", ".bin"), ("prefetch", ".pf"), ("evtx", ".evtx"), ("amcache", ".hve")],
)
def test_corrupted_binary_is_a_failed_run(adapter, tmp_path, kind, suffix):
    path = tmp_path / ("invalid" + suffix)
    path.write_bytes(b"not a valid artifact")
    result = adapter.load_file(path, kind)
    assert result.runs[0].status == RunStatus.FAILED
    assert result.events == [] and result.runs[0].error


def test_prefetch_volume_and_directory_bounds(adapter, tmp_path):
    data = bytearray((FIXTURES / "sample-v30.pf").read_bytes())
    offset = len(data)
    device = r"\Device\HarddiskVolume3".encode("utf-16-le")
    directory = "C:\\Temp".encode("utf-16-le")
    volume = bytearray(96)
    struct.pack_into("<IIQIIIII", volume, 0, 96, len(device) // 2, 0, 0xAABBCCDD, 0, 0, 96 + len(device), 1)
    volume.extend(device + struct.pack("<H", len(directory) // 2) + directory + b"\0\0")
    struct.pack_into("<III", data, 108, offset, 1, len(volume))
    data.extend(volume)
    struct.pack_into("<I", data, 12, len(data))
    path = tmp_path / "volume.pf"
    path.write_bytes(data)
    result = adapter.load_file(path, "prefetch")
    assert result.runs[0].status == RunStatus.SUCCESS, result.runs[0].error
    assert result.events[0].prefetch.volumes[0]["serial"] == "AABBCCDD"
    assert result.events[0].prefetch.directories == ["C:\\Temp"]
    struct.pack_into("<I", data, offset, len(data) + 100)
    path.write_bytes(data)
    assert adapter.load_file(path, "prefetch").runs[0].status == RunStatus.FAILED


def test_file_content_hash_is_not_artifact_metadata_guess(adapter, tmp_path):
    path = tmp_path / "content.bin"
    path.write_bytes(b"inert recovered content\n")
    adapter.context.logical_path = "C:\\Temp\\payload.dll"
    event = adapter.load_file(path, "file").events[0]
    assert event.file.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert event.file.path == adapter.context.logical_path and event.file.size == path.stat().st_size
