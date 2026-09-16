import hashlib
import json
from pathlib import Path

import pytest

from engine.collectors.memory.extended import MemoryImportAdapter
from engine.parsers.volatility.registry import canonical_plugin, discover_plugins, filename_plugin
from schemas.events import Event
from schemas.imports import ArtifactContext, RunStatus

FIXTURES = Path(__file__).parent / "fixtures" / "memory_extended"
BASE = Path(__file__).parent / "fixtures" / "volatility"
PLUGINS = sorted(path.stem for path in FIXTURES.glob("*.json"))
REQUIRED = {
    "psscan": ["PID", "ImageFileName"],
    "envars": ["PID", "Variable", "Value"],
    "handles": ["PID", "Type", "Offset"],
    "filescan": ["Offset", "Name"],
    "vadinfo": ["PID", "Start VPN"],
    "malfind": ["PID", "Start VPN"],
    "svcscan": ["Name"],
    "svclist": ["Name"],
    "amcache": ["EntryType"],
    "userassist": ["Path"],
    "shimcachemem": ["File Path"],
    "modules": ["Name", "Base"],
    "modscan": ["Name", "Base"],
    "driverscan": ["Offset"],
    "callbacks": ["Type", "Callback"],
    "dumpfiles": ["FileObject", "Result"],
}


@pytest.fixture
def adapter():
    return MemoryImportAdapter(
        ArtifactContext(
            acquisition_id="extended-image",
            extracted_at="2026-09-16T09:35:00Z",
            hostname="workstation-01",
            tool_version="2.28.0",
            recovered_directory=str(FIXTURES),
        )
    )


@pytest.mark.parametrize("name", PLUGINS)
def test_memory_plugin_normal(adapter, name):
    path = FIXTURES / f"{name}.json"
    before = path.read_bytes()
    result = adapter.load_exports([(filename_plugin(name), path)])
    assert result.runs[0].status == RunStatus.SUCCESS, result.runs[0].error
    assert len(result.events) == 1
    event = result.events[0]
    assert Event.model_validate_json(event.model_dump_json()) == event
    assert event.source == "memory"
    assert event.provenance[0].plugin == filename_plugin(name)
    assert event.provenance[0].source_artifact.sha256 == hashlib.sha256(before).hexdigest()
    assert event.provenance[0].source_artifact.size == len(before)
    assert event.provenance[0].memory_image_id == "extended-image"
    assert event.raw == {k: v for k, v in json.loads(before)[0].items() if k != "__children"}
    assert path.read_bytes() == before


@pytest.mark.parametrize("name", PLUGINS)
def test_memory_plugin_malformed(adapter, tmp_path, name):
    path = tmp_path / "invalid.json"
    path.write_text('[{"unrelated": "not the claimed artifact"}]')
    result = adapter.load_exports([(filename_plugin(name), path)])
    assert result.events == []
    assert result.runs[0].status == RunStatus.FAILED
    assert result.runs[0].error


@pytest.mark.parametrize("name", PLUGINS)
def test_memory_plugin_missing_optional(adapter, tmp_path, name):
    raw = json.loads((FIXTURES / f"{name}.json").read_text())[0]
    minimal = {key: raw[key] for key in REQUIRED[name]}
    path = tmp_path / "minimal.json"
    path.write_text(json.dumps([minimal]))
    result = adapter.load_exports([(filename_plugin(name), path)])
    assert result.runs[0].status == RunStatus.SUCCESS, result.runs[0].error
    assert len(result.events) == 1
    assert result.events[0].timestamp_semantics == "extraction_time"


def test_combined_owner_scan_comparisons_and_exact_64_bit_addresses(adapter):
    exports = [
        (filename_plugin(path.stem), path)
        for directory in (BASE, FIXTURES)
        for path in sorted(directory.glob("*.json"))
    ]
    result = adapter.load_exports(exports)
    assert all(run.status == RunStatus.SUCCESS for run in result.runs), result.runs
    assert len(result.runs) == 21 and len(result.events) == 24
    scan = next(event for event in result.events if event.type == "process_scan")
    process = next(
        event for event in result.events if event.type == "process_start" and event.process.pid == 4120
    )
    assert scan.event_id != process.event_id
    assert scan.process.instance_id == process.process.instance_id
    assert scan.metadata["pslist_found"] is True
    handles = next(event for event in result.events if event.handle)
    assert handles.process.instance_id == process.process.instance_id
    assert handles.handle.object_address == hex(18446603336221196288)
    assert handles.file.file_object == handles.handle.object_address
    assert {p.plugin for p in handles.provenance} >= {"windows.handles", "windows.pslist", "windows.cmdline"}
    modules = [event for event in result.events if event.type == "kernel_module_observation"]
    assert len(modules) == 2
    assert modules[0].module.base_address_hex == hex(18446735277616529408)
    assert next(e for e in modules if e.artifact_type == "modscan").metadata["modules_found"] is True
    assert next(e for e in modules if e.artifact_type == "modules").metadata["modscan_found"] is True
    suspicious = next(event for event in result.events if event.artifact_type == "suspicious_memory_region")
    assert suspicious.memory_region.hex_preview and suspicious.memory_region.disassembly_preview
    assert "malicious" not in suspicious.metadata
    recovered = next(event for event in result.events if event.type == "recovered_file")
    assert recovered.file.sha256 == hashlib.sha256((FIXTURES / "recovered.txt").read_bytes()).hexdigest()
    assert recovered.file.size == (FIXTURES / "recovered.txt").stat().st_size


def test_scan_only_signal_and_absent_export_are_not_verdicts(adapter, tmp_path):
    raw = json.loads((FIXTURES / "psscan.json").read_text())
    raw[0]["PID"] = 6152
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(raw))
    result = adapter.load_exports(
        [("windows.pslist", BASE / "pslist.json"), ("windows.psscan", path)], expected=["windows.svclist"]
    )
    scan = next(event for event in result.events if event.type == "process_scan")
    assert scan.metadata["pslist_found"] is False
    assert scan.metadata["signal"] == "psscan_only"
    assert result.runs[-1].status == RunStatus.SKIPPED
    without_list = adapter.load_exports([("windows.psscan", path)])
    assert without_list.events[0].metadata["pslist_found"] is None


def test_failure_does_not_erase_other_plugins(adapter, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("broken")
    result = adapter.load_exports(
        [("windows.pslist", BASE / "pslist.json"), ("windows.handles", path), ("windows.missing", path)]
    )
    assert len(result.events) == 3
    assert [run.status for run in result.runs] == [RunStatus.SUCCESS, RunStatus.FAILED, RunStatus.FAILED]
    assert all(run.error for run in result.runs[1:])


def test_dumpfiles_rejects_path_escape_and_missing_bytes(adapter, tmp_path):
    for output in ("../outside.txt", "absent.bin"):
        path = tmp_path / "dump.json"
        path.write_text(json.dumps([{"FileObject": 123, "Result": output}]))
        result = adapter.load_exports([("windows.dumpfiles", path)])
        assert result.runs[0].status == RunStatus.FAILED
        assert result.events == []


def test_namespace_aliases_and_unavailable_discovery():
    assert canonical_plugin("windows.malfind.Malfind") == "windows.malware.malfind"
    assert canonical_plugin("windows.amcache.Amcache") == "windows.registry.amcache"
    result = discover_plugins("/definitely/not/installed/vol")
    assert result["error"] and len(result["plugins"]) == 21
    assert all(plugin["supported"] and not plugin["available"] for plugin in result["plugins"])
