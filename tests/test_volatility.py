import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from engine.collectors.memory import MemoryCollector
from engine.collectors.memory.volatility import Volatility3Adapter
from engine.correlation import CorrelationEngine, related_ids
from engine.correlation.temporal import TemporalRule
from engine.graph import build_graph
from engine.parsers.volatility import VolatilityParser
from engine.parsers.volatility.rows import ImportContext, VolatilityImportError
from engine.service import AnalysisService
from engine.storage import SQLiteRepository
from schemas.events import Event
from schemas.results import AnalysisRequest, CaseCreate

FIXTURES = Path(__file__).parent / "fixtures" / "volatility"


@pytest.fixture
def adapter():
    return Volatility3Adapter(
        ImportContext(
            memory_image_id="fixture-memory-01",
            extraction_timestamp="2026-09-16T09:35:00Z",
            hostname="workstation-01",
            volatility_version="2.28.2",
        )
    )


def write(tmp_path, name, rows):
    target = tmp_path / name
    target.write_text(json.dumps(rows))
    return target


@pytest.mark.parametrize(
    "plugin,count", [("pslist", 3), ("pstree", 3), ("cmdline", 3), ("netscan", 2), ("dlllist", 3)]
)
def test_individual_plugins(adapter, plugin, count):
    result = adapter.load_file(FIXTURES / f"{plugin}.json", f"windows.{plugin}")
    assert len(result.events) == count
    assert all(event.source == "memory" for event in result.events)
    assert all(Event.model_validate_json(event.model_dump_json()) == event for event in result.events)


def test_merge_process_fields_and_references(adapter):
    result = adapter.load_directory(FIXTURES)
    assert len(result.events) == 8 and result.input_rows == 14
    processes = [event for event in result.events if event.type == "process_start"]
    assert len(processes) == 3
    process = next(event for event in processes if event.process.pid == 4120)
    assert process.process.ppid == 3300
    assert process.process.name == "powershell.exe"
    assert "a.ps1" in process.process.command_line
    assert process.process.path.endswith("powershell.exe")
    assert {reference.plugin for reference in process.provenance} == {
        "windows.pslist",
        "windows.pstree",
        "windows.cmdline",
    }
    assert process.process.parent_instance_id == next(
        event.process.instance_id for event in processes if event.process.pid == 3300
    )


def test_pstree_nested_reference_and_parent_graph(adapter):
    events = adapter.load_file(FIXTURES / "pstree.json", "windows.pstree.PsTree").events
    child = next(event for event in events if event.process.pid == 4120)
    assert child.raw_reference.locator == "/0/__children/0/__children/0"
    graph = build_graph(events, CorrelationEngine().correlate(events))
    nodes = {node.id: node for node in graph.nodes}
    parents = [edge for edge in graph.edges if edge.kind == "PARENT_OF"]
    assert len(parents) == 2
    assert any(
        "WINWORD" in nodes[edge.source].label and "powershell" in nodes[edge.target].label for edge in parents
    )


def test_socket_owner_and_module_graph(adapter):
    events = adapter.load_directory(FIXTURES).events
    process = next(event for event in events if event.type == "process_start" and event.process.pid == 4120)
    socket = next(event for event in events if event.network and event.network.dst_port == 443)
    assert socket.process.instance_id == process.process.instance_id
    assert socket.network.protocol == "TCP" and socket.network.state == "ESTABLISHED"
    assert socket.network.src_ip == "192.168.0.15" and socket.network.src_port == 50321
    assert socket.network.dst_ip == "185.10.10.5"
    assert socket.timestamp.isoformat() == "2026-09-16T09:31:29.300000+00:00"
    module = next(event for event in events if event.module and event.process.pid == 4120)
    assert module.module.base_address > 0 and module.module.size > 0 and module.file.path
    graph = build_graph(events, CorrelationEngine().correlate(events))
    assert len([edge for edge in graph.edges if edge.kind == "LOADED"]) == 3
    assert len([edge for edge in graph.edges if edge.kind == "CONNECTED_TO"]) == 1


def test_provenance_preserves_every_original_row(adapter):
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in FIXTURES.glob("*.json")}
    result = adapter.load_directory(FIXTURES)
    references = {}
    for event in result.events:
        for reference in event.provenance:
            path = Path(reference.source_artifact.path)
            raw = json.loads(path.read_text())
            for component in reference.raw_reference.locator.strip("/").split("/"):
                raw = raw[int(component)] if isinstance(raw, list) else raw[component]
            assert reference.raw == {key: value for key, value in raw.items() if key != "__children"}
            assert reference.source_artifact.sha256 == hashes[path.name]
            assert reference.memory_image_id == "fixture-memory-01"
            assert reference.tool_version == "2.28.2"
            assert reference.parser.name == "Volatility3Adapter"
            assert reference.extraction_timestamp.isoformat() == "2026-09-16T09:35:00+00:00"
            references[(path.name, reference.raw_reference.locator)] = reference
    assert len(references) == result.input_rows
    assert hashes == {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in FIXTURES.glob("*.json")
    }


def test_duplicate_rows_and_exports_merge_without_losing_provenance(adapter, tmp_path):
    rows = json.loads((FIXTURES / "cmdline.json").read_text())
    path = write(tmp_path, "cmdline.json", [*rows, rows[-1]])
    result = adapter.load_exports([("windows.cmdline", path), ("windows.cmdline.CmdLine", path)])
    assert len(result.events) == 3
    process = next(event for event in result.events if event.process.pid == 4120)
    assert len(process.provenance) == 2


@pytest.mark.parametrize(
    "plugin,fields",
    [
        ("pslist", ["Threads", "Handles", "SessionId", "Wow64", "CreateTime", "ExitTime", "PPID"]),
        ("cmdline", ["Args"]),
        ("netscan", ["PID", "Owner", "Created", "State"]),
        ("dlllist", ["Size", "LoadTime", "LoadCount", "Path"]),
    ],
)
def test_missing_optional_fields(adapter, tmp_path, plugin, fields):
    row = json.loads((FIXTURES / f"{plugin}.json").read_text())[0]
    for key in fields:
        row[key] = None
    result = adapter.load_file(write(tmp_path, "optional.json", [row]), f"windows.{plugin}")
    assert len(result.events) == 1
    event = result.events[0]
    if plugin in {"pslist", "cmdline", "netscan", "dlllist"}:
        assert event.timestamp_semantics == "extraction_time"
    assert event.provenance[0].raw == {key: value for key, value in row.items() if key != "__children"}


def test_no_synthetic_time_correlation(adapter):
    events = adapter.load_file(FIXTURES / "cmdline.json", "windows.cmdline").events
    assert TemporalRule().evaluate(events[0], events[1]) == []
    assert CorrelationEngine().correlate(events) == []


def test_field_variants_hex_ipv6_and_explicit_utc(adapter, tmp_path):
    row = {
        "PID": "4120",
        "Process": "powershell.exe",
        "DllBase": "0x7ff00000",
        "SizeOfImage": "0x1000",
        "BaseDllName": "a.dll",
        "FullDllName": "C:\\a.dll",
        "Load Time": "2026-09-16 09:31:26.000 UTC",
    }
    module = adapter.load_file(write(tmp_path, "dll.json", [row]), "windows.dlllist.DllList").events[0]
    assert module.module.base_address == 0x7FF00000 and module.module.size == 4096
    row = {
        "PID": None,
        "Protocol": "TCPv6",
        "LocalAddress": "[2001:db8::1]",
        "LocalPort": "443",
        "RemoteAddr": "*",
        "RemotePort": "0",
        "State": "LISTENING",
        "Created": "N/A",
    }
    socket = adapter.load_file(write(tmp_path, "net.json", [row]), "windows.netscan").events[0]
    assert socket.network.src_ip == "2001:db8::1"
    assert socket.network.dst_ip is None and socket.process is None
    assert all(edge.kind != "CONNECTED_TO" for edge in build_graph([socket], []).edges)


@pytest.mark.parametrize(
    "content",
    [
        "broken",
        "{}",
        "[]",
        '[{"event_id":"a"}]',
        '[{"PID":1}]',
        '[{"PID":1,"PID":2,"ImageFileName":"a","CreateTime":null}]',
        '[{"PID":1,"ImageFileName":"a","__children":{}}]',
    ],
)
def test_invalid_json_shape_or_required_data(adapter, tmp_path, content):
    path = tmp_path / "bad.json"
    path.write_text(content)
    with pytest.raises(VolatilityImportError):
        adapter.load_file(path, "windows.pslist")


@pytest.mark.parametrize("plugin", ["windows.psscan", "linux.pslist", "pslist", "windows.pslist.BadClass"])
def test_unknown_plugin(adapter, plugin):
    with pytest.raises(VolatilityImportError, match="Unsupported Volatility plugin"):
        adapter.load_file(FIXTURES / "pslist.json", plugin)


@pytest.mark.parametrize(
    "field,value",
    [("PID", True), ("PID", -1), ("PID", 1.2), ("CreateTime", "2026-09-16T09:31:20"), ("PPID", "bad")],
)
def test_invalid_values_are_not_coerced(adapter, tmp_path, field, value):
    row = json.loads((FIXTURES / "pslist.json").read_text())[0]
    row[field] = value
    with pytest.raises(VolatilityImportError):
        adapter.load_file(write(tmp_path, "bad.json", [row]), "windows.pslist")


def test_conflicting_pid_lifetimes_and_fields(adapter, tmp_path):
    rows = json.loads((FIXTURES / "pslist.json").read_text())
    original = rows[-1]
    reused = {**original, "CreateTime": "2026-09-15T09:31:25Z", "Offset(V)": 50000}
    pslist = write(tmp_path, "pslist.json", [original, reused])
    assert len(adapter.load_file(pslist, "windows.pslist").events) == 2
    with pytest.raises(VolatilityImportError, match="multiple lifetimes"):
        adapter.load_exports([("windows.pslist", pslist), ("windows.cmdline", FIXTURES / "cmdline.json")])
    conflicting = write(tmp_path, "conflict.json", [original, {**original, "ImageFileName": "other.exe"}])
    with pytest.raises(VolatilityImportError, match="Conflicting name"):
        adapter.load_file(conflicting, "windows.pslist")


def test_nested_parent_disagreement(adapter, tmp_path):
    rows = json.loads((FIXTURES / "pstree.json").read_text())
    rows[0]["__children"][0]["PPID"] = 999
    with pytest.raises(VolatilityImportError, match="hierarchy disagrees"):
        adapter.load_file(write(tmp_path, "tree.json", rows), "windows.pstree")


def test_context_scope_prevents_pid_collision(adapter):
    other = Volatility3Adapter(adapter.context.model_copy(update={"memory_image_id": "different-image"}))
    a = adapter.load_file(FIXTURES / "pslist.json", "windows.pslist").events[0]
    b = other.load_file(FIXTURES / "pslist.json", "windows.pslist").events[0]
    assert a.process.instance_id != b.process.instance_id
    assert CorrelationEngine().correlate([a, b]) == []


def test_adapter_without_hostname_still_associates_process_socket(adapter):
    adapter = Volatility3Adapter(adapter.context.model_copy(update={"hostname": None}))
    events = adapter.load_directory(FIXTURES).events
    process = next(event for event in events if event.type == "process_start" and event.process.pid == 4120)
    socket = next(event for event in events if event.network and event.network.dst_port == 443)
    assert CorrelationEngine().correlate([process, socket])[0].score >= 55


def test_parser_facade_through_collector(adapter):
    events = MemoryCollector().collect(
        FIXTURES / "pslist.json", VolatilityParser("windows.pslist", adapter.context)
    )
    assert len(events) == 3


def test_full_sample_cross_source_integration_and_persistence(adapter, sample, tmp_path):
    memory = adapter.load_directory(FIXTURES).events
    events = memory + [event for event in sample if event.source != "memory"]
    root = next(event for event in memory if event.type == "process_start" and event.process.pid == 4120)
    repository = SQLiteRepository(tmp_path / "memory.sqlite3")
    case = repository.create_case(CaseCreate(name="Memory Adapter Integration"))
    repository.add_events(case.case_id, events)
    result = AnalysisService(repository).analyze(case.case_id, AnalysisRequest(root_event_id=root.event_id))
    ids = related_ids(result.correlations, root.event_id)
    assert {"DISK-SCRIPT", "DISK-USN", "NET-DNS", "NET-TLS"} <= ids
    assert not any(identifier.startswith("NOISE") for identifier in ids)
    assert any(
        reason.rule == "command_line_file_path" for edge in result.correlations for reason in edge.reasons
    )
    assert any(reason.rule == "same_socket_tuple" for edge in result.correlations for reason in edge.reasons)
    persisted = SQLiteRepository(tmp_path / "memory.sqlite3").events(case.case_id)
    assert next(event for event in persisted if event.event_id == root.event_id).provenance == root.provenance


def test_cli_real_fixture_import_and_failure_atomicity(tmp_path):
    db, output = tmp_path / "cli.sqlite3", tmp_path / "events.json"
    command = [
        sys.executable,
        "-m",
        "engine.cli",
        "import-memory",
        str(FIXTURES),
        "--image-id",
        "cli-image",
        "--extracted-at",
        "2026-09-16T09:35:00Z",
        "--db",
        str(db),
        "--output",
        str(output),
    ]
    run = subprocess.run(command, capture_output=True, text=True, check=True)
    result = json.loads(run.stdout)
    assert result["imported"] == 8
    events = [Event.model_validate(item) for item in json.loads(output.read_text())]
    assert len(events) == 8 and all(event.provenance for event in events)
    assert SQLiteRepository(db).get_case(result["case_id"]).event_count == 8
    invalid = subprocess.run([*command[:4], "--plugin", "bad", *command[4:]], capture_output=True, text=True)
    assert invalid.returncode != 0
    assert len(SQLiteRepository(db).list_cases()) == 1
