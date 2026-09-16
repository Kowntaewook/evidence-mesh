import hashlib
import json
from pathlib import Path

import pytest

from engine.correlation import CorrelationEngine, related_ids
from engine.graph import build_graph
from engine.normalization import normalize_events
from engine.parsers.json_events import JsonEventParser
from engine.parsers.ntfs import MFTParser, USNParser
from engine.parsers.pcap import PCAPParser
from engine.parsers.prefetch import PrefetchParser
from engine.parsers.volatility import VolatilityParser
from engine.sample import DEFAULT_SAMPLE_DIR, load_sample


def test_full_incident_and_noise(sample):
    edges = CorrelationEngine().correlate(sample)
    connected = related_ids(edges, "MEM-PS")
    assert connected == {
        "MEM-EXPLORER",
        "MEM-PS",
        "MEM-SOCKET",
        "DISK-ZIP",
        "DISK-SCRIPT",
        "DISK-USN",
        "DISK-PREFETCH",
        "NET-DNS",
        "NET-TLS",
    }
    assert not any("NOISE" in edge.source_event or "NOISE" in edge.target_event for edge in edges)
    pairs = {frozenset((edge.source_event, edge.target_event)): edge for edge in edges}
    assert pairs[frozenset(("MEM-PS", "DISK-SCRIPT"))].score >= 80
    assert pairs[frozenset(("MEM-SOCKET", "NET-TLS"))].score == 90
    assert pairs[frozenset(("NET-DNS", "NET-TLS"))].score == 80
    graph = build_graph(sample, edges)
    kinds = {node.kind.value for node in graph.nodes}
    assert {"Process", "File", "IP", "Domain", "User", "Event"} <= kinds
    assert len({node.id for node in graph.nodes}) == len(graph.nodes)
    assert len({edge.id for edge in graph.edges}) == len(graph.edges)
    node_ids = {node.id for node in graph.nodes}
    assert all(edge.source in node_ids and edge.target in node_ids for edge in graph.edges)
    scored = [edge for edge in graph.edges if edge.kind == "CORRELATED_WITH"]
    assert len(scored) == len(edges) and all(edge.reasons for edge in scored)


def test_evidence_bytes_unchanged():
    paths = sorted(DEFAULT_SAMPLE_DIR.glob("*.json"))
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    events = load_sample()
    CorrelationEngine().correlate(events)
    assert before == {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    assert all(event.raw_reference and event.parser and event.source_artifact for event in events)
    assert all(event.attributes["import_reference"]["sha256"] in before.values() for event in events)


@pytest.mark.parametrize(
    "parser", [MFTParser(), USNParser(), PCAPParser(), PrefetchParser(), VolatilityParser()]
)
def test_unimplemented_parsers_fail_explicitly(parser):
    with pytest.raises(NotImplementedError, match="stub"):
        parser.parse(Path("unused"))


@pytest.mark.parametrize("contents", ["[]", "{}", "[1]", "invalid json"])
def test_bad_json_is_not_success(tmp_path, contents):
    artifact = tmp_path / "events.json"
    artifact.write_text(contents)
    with pytest.raises(ValueError):
        JsonEventParser().parse(artifact)


def test_import_nullable_provenance_and_history(tmp_path, make_event):
    event = make_event().model_dump(mode="json")
    previous = {"path": "earlier.json", "sha256": "b" * 64, "json_pointer": "/2"}
    event["attributes"]["import_reference"] = previous
    path = tmp_path / "events.json"
    path.write_text(json.dumps([event]))
    imported = normalize_events(JsonEventParser().parse(path))[0]
    assert imported.source_artifact.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert imported.raw_reference.locator == "/0"
    assert imported.parser.name == "evidencemesh-json"
    assert imported.attributes["import_history"] == [previous]


def test_import_never_invents_original_artifact_record(tmp_path, make_event):
    record = make_event(source_artifact={"artifact_id": "disk-1", "kind": "$MFT"}).model_dump(mode="json")
    path = tmp_path / "events.json"
    path.write_text(json.dumps([record]))
    imported = normalize_events(JsonEventParser().parse(path))[0]
    assert imported.source_artifact.artifact_id == "disk-1"
    assert imported.raw_reference is None
    assert imported.attributes["import_reference"]["json_pointer"] == "/0"
