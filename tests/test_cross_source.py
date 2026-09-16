import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
from datetime import timedelta
from itertools import combinations
from pathlib import Path

import pytest

from engine.correlation import CorrelationEngine
from engine.correlation.artifacts import negative_reasons
from engine.correlation.index import EventIndex
from engine.ingestion.service import ImportService
from engine.service import AnalysisService
from engine.storage import SQLiteRepository
from schemas.imports import ArtifactContext, ImportRequest
from schemas.results import AnalysisRequest, CaseCreate, Correlation, Reason

ROOT = Path(__file__).parents[1]
CASE = ROOT / "samples" / "cross_source"
CONTEXT = ArtifactContext(
    acquisition_id="test-disk",
    extracted_at="2026-09-16T09:35:00Z",
    hostname="workstation-01",
    volume_id="volume-C",
)


@pytest.fixture
def investigation(tmp_path):
    if not shutil.which("tshark"):
        pytest.skip("tshark is not installed")
    repository = SQLiteRepository(tmp_path / "case.sqlite3")
    case = repository.create_case(CaseCreate(name="Cross-source"))
    reports = ImportService(repository).import_case(case.case_id, CASE)
    assert all(report.status == "SUCCESS" for report in reports)
    events = repository.events(case.case_id)
    root = next(
        e for e in events if e.source == "memory" and e.type == "process_start" and e.process.pid == 4120
    )
    return repository, case, events, root


def test_cross_source_chain_noise_and_typed_graph(investigation):
    repository, case, events, root = investigation
    service = AnalysisService(repository)
    result = service.analyze(case.case_id, AnalysisRequest(root_event_id=root.event_id))
    relevant = service.timeline(case.case_id, root.event_id).events
    assert len(relevant) >= 20
    noise = [
        e
        for e in events
        if e.raw.get("FixtureRole") == "noise"
        or e.network
        and (e.network.src_ip or "").startswith("192.0.2.")
    ]
    assert len(noise) >= 20
    assert not {e.event_id for e in noise} & {e.event_id for e in relevant}
    assert {e.source for e in relevant} == {"memory", "disk", "network"}
    assert {
        "handle_observation",
        "socket",
        "file_created",
        "prefetch_execution",
        "dns_response",
        "tls_client_hello",
        "network_flow",
        "recovered_file",
    } <= {e.type for e in relevant}
    reasons = {reason.rule for edge in result.correlations for reason in edge.reasons}
    assert {
        "same_sha256",
        "same_mft_reference",
        "same_file_object",
        "handle_file_reference",
        "same_socket_tuple",
        "tls_sni_domain",
        "cross_source_corroboration",
        "command_line_file_path",
        "prefetch_executable_path",
        "registry_file_reference",
    } <= reasons
    for edge in result.correlations:
        assert edge.raw_score == sum(r.score for r in edge.reasons)
        assert edge.score == max(0, min(100, edge.raw_score))
    graph = service.graph(case.case_id)
    assert {
        "Process",
        "File",
        "MFTRecord",
        "Domain",
        "IP",
        "Socket",
        "NetworkFlow",
        "Service",
        "RegistryArtifact",
        "DLL",
        "Module",
        "Driver",
        "MemoryRegion",
        "Event",
    } <= {n.kind for n in graph.nodes}
    assert {
        "PARENT_OF",
        "EXECUTED",
        "OPENED",
        "LOADED",
        "CONNECTED_TO",
        "RESOLVED_TO",
        "REFERENCES",
        "USES_BINARY",
        "ASSOCIATED_WITH",
        "EXTRACTED_FROM",
    } <= {e.kind for e in graph.edges}
    assert all(e.provenance and e.reasons and e.timestamp for e in graph.edges)
    with repository.connection() as db:
        for table in (
            "events",
            "imports",
            "parser_runs",
            "evidence_sources",
            "entities",
            "correlations",
            "correlation_reasons",
            "graph_nodes",
            "graph_edges",
        ):
            assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] > 0


def test_indexed_candidate_completeness_and_determinism(investigation, monkeypatch):
    _, _, events, _ = investigation
    engine = CorrelationEngine()
    indexed = engine.correlate(events)
    assert engine.stats["candidate_pairs"] < engine.stats["all_pairs"] / 2
    assert {
        "pid",
        "process_name",
        "path",
        "filename",
        "hash",
        "ip",
        "domain",
        "port",
        "mft",
        "timestamp_bucket",
    } <= engine.stats["indexes"].keys()
    assert indexed == engine.correlate(list(reversed(events)))
    monkeypatch.setattr(EventIndex, "pairs", lambda self: list(combinations(range(len(self.events)), 2)))
    assert indexed == CorrelationEngine().correlate(events)


def test_process_lifetime_negative_precision_and_raw_score(make_event):
    process = {"pid": 1, "creation_time": "2026-09-16T09:31:20Z", "exit_time": "2026-09-16T09:31:26Z"}
    a = make_event(process=process, timestamp_precision=2)
    b = make_event("B", process=process, timestamp="2026-09-16T09:31:25.5Z")
    result = CorrelationEngine().correlate([a, b])[0]
    assert any(r.rule == "timestamp_precision_penalty" and r.score == -10 for r in result.reasons)
    b.timestamp += timedelta(seconds=2)
    assert CorrelationEngine().correlate([a, b]) == []
    assert any(r.rule == "process_lifetime_conflict" for r in negative_reasons(a, b))
    b.hostname = "different"
    assert any(r.rule == "hostname_conflict" for r in negative_reasons(a, b))
    value = Correlation(
        source_event="A",
        target_event="B",
        score=0,
        reasons=[Reason(rule="conflict", score=-50, details="Known conflict")],
    )
    assert value.raw_score == -50


def test_long_flow_overlap_and_exact_hash_are_indexed(make_event):
    net = {
        "src_ip": "10.0.0.5",
        "src_port": 1234,
        "dst_ip": "203.0.113.20",
        "dst_port": 443,
        "protocol": "TCP",
    }
    flow = make_event("FLOW", source="network", network={**net, "end_time": "2026-09-16T10:31:25Z"})
    socket = make_event("SOCKET", network=net, timestamp="2026-09-16T10:00:00Z")
    result = CorrelationEngine().correlate([flow, socket])
    assert result and any(r.rule == "flow_temporal_overlap" for r in result[0].reasons)
    a = make_event(file={"sha256": "a" * 64})
    b = make_event("HASH", source="disk", file={"sha256": "a" * 64}, timestamp="2020-01-01T00:00:00Z")
    assert CorrelationEngine().correlate([a, b])[0].score == 60


def test_disk_only_api_import_failure_audit_and_pagination(client):
    case = client.post("/cases", json={"name": "Disk only"}).json()["case_id"]
    base = f"/cases/{case}"
    body = {
        "path": str(CASE / "disk/artifacts/mft.json"),
        "format": "mft",
        "context": CONTEXT.model_dump(mode="json"),
    }
    imported = client.post(base + "/import/disk", json=body).json()
    assert imported["status"] == "SUCCESS" and imported["imported"] == 13
    assert len(client.get(base + "/files", params={"limit": 5, "offset": 5}).json()) == 5
    assert client.get(base + "/processes").json() == []
    assert client.get(base + "/network").json() == []
    assert len(client.get(base + "/events", params={"artifact_type": "$MFT", "limit": 3}).json()) == 3
    assert client.get(base + "/timeline", params={"source": "memory"}).json()["events"] == []
    body["path"] = str(CASE / "missing.csv")
    failed = client.post(base + "/import/disk", json=body).json()
    assert failed["status"] == "FAILED" and failed["runs"][0]["error"]
    runs = client.get(base + "/parser-runs").json()
    assert [run["status"] for run in runs] == ["SUCCESS", "FAILED"]
    assert len(client.get(base + "/imports").json()) == 2
    assert client.get(base).json()["event_count"] == 13


def test_duplicate_import_failure_persists_without_losing_events(tmp_path):
    repository = SQLiteRepository(tmp_path / "case.db")
    case = repository.create_case(CaseCreate(name="Atomic import"))
    service = ImportService(repository)
    request = ImportRequest(path=str(CASE / "disk/artifacts/usn.json"), context=CONTEXT)
    assert service.import_evidence(case.case_id, "usn", request).status == "SUCCESS"
    failed = service.import_evidence(case.case_id, "usn", request)
    assert failed.status == "FAILED" and failed.imported == 0 and "Storage" in failed.runs[0].error
    assert repository.get_case(case.case_id).event_count == 1
    assert len(repository.parser_runs(case.case_id)) == 2


def test_v1_database_migration_preserves_original_json(tmp_path, make_event):
    path, event = tmp_path / "old.db", make_event(process={"pid": 42})
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE cases(case_id TEXT PRIMARY KEY,name TEXT,description TEXT,created_at TEXT,
                               revision INTEGER DEFAULT 0,analysis_revision INTEGER);
            CREATE TABLE events(case_id TEXT,event_id TEXT,timestamp TEXT,source TEXT,data TEXT,
                                PRIMARY KEY(case_id,event_id));
            PRAGMA user_version=1;
        """)
        db.execute(
            "INSERT INTO cases VALUES (?,?,?,?,?,?)", ("old", "Old", "", event.timestamp.isoformat(), 1, None)
        )
        db.execute(
            "INSERT INTO events VALUES (?,?,?,?,?)",
            ("old", event.event_id, event.timestamp.isoformat(), "memory", event.model_dump_json()),
        )
    repository = SQLiteRepository(path)
    assert repository.events("old") == [event]
    assert repository.query_events("old", pid=42) == [event]
    with repository.connection() as db:
        assert db.execute("SELECT data FROM events").fetchone()[0] == event.model_dump_json()
        assert db.execute("PRAGMA user_version").fetchone()[0] == 3


def test_cross_source_cli_workflow(tmp_path):
    if not shutil.which("tshark"):
        pytest.skip("tshark is not installed")
    db = tmp_path / "cli.db"
    prefix = [sys.executable, "-m", "engine.cli"]
    result = subprocess.run(
        [*prefix, "import-case", str(CASE), "--db", str(db)], capture_output=True, text=True, check=True
    )
    report = json.loads(result.stdout)
    assert len(report["imports"]) == 8 and all(r["status"] == "SUCCESS" for r in report["imports"])
    for command in ("correlate", "timeline", "graph", "parser-runs"):
        run = subprocess.run(
            [*prefix, command, "--db", str(db), "--case-id", report["case_id"]],
            capture_output=True,
            text=True,
            check=True,
        )
        assert json.loads(run.stdout)


def test_original_102_tests_are_byte_identical():
    manifest = ROOT / "data/baseline-v02/sha256.json"
    if not manifest.exists():
        pytest.skip("Local baseline snapshot is not distributed")
    hashes = json.loads(manifest.read_text())
    for name in (
        "conftest.py",
        "test_schema.py",
        "test_rules.py",
        "test_sample.py",
        "test_api_storage.py",
        "test_cli.py",
        "test_volatility.py",
    ):
        relative = "tests/" + name
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == hashes[relative]
