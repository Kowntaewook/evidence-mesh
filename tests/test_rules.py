from datetime import timedelta

import pytest

from engine.correlation import CorrelationEngine
from engine.correlation.file import FileRule
from engine.correlation.network import NetworkRule
from engine.correlation.process import ProcessRule
from engine.correlation.temporal import TemporalRule
from schemas.results import Correlation, Reason


@pytest.mark.parametrize(
    ("delta", "score"),
    [
        (0, 30),
        (2, 30),
        (2.001, 25),
        (5, 25),
        (5.001, 15),
        (30, 15),
        (30.001, 5),
        (60, 5),
        (60.001, 0),
        (-1.2, 30),
    ],
)
def test_temporal_boundaries(make_event, delta, score):
    left = make_event()
    right = make_event("B", timestamp=left.timestamp + timedelta(seconds=delta))
    reasons = TemporalRule().evaluate(left, right)
    assert sum(reason.score for reason in reasons) == score
    assert reasons == TemporalRule().evaluate(right, left)


def test_process_identity_and_parent(make_event):
    proc = {
        "pid": 4120,
        "name": "powershell.exe",
        "path": r"C:\Windows\powershell.exe",
        "creation_time": "2026-09-16T09:31:20Z",
        "command_line": "powershell.exe",
    }
    a, b = make_event(process=proc), make_event("B", process=proc, source="disk")
    reasons = ProcessRule().evaluate(a, b)
    assert {r.rule for r in reasons} == {
        "same_process_id",
        "same_process_creation",
        "same_process_name",
        "same_executable_path",
        "same_command_line",
    }
    child = make_event("C", process={"pid": 5000, "ppid": 4120, "creation_time": "2026-09-16T09:31:24Z"})
    assert ProcessRule().evaluate(a, child)[0].rule == "parent_process"


@pytest.mark.parametrize(
    "patch",
    [
        {"hostname": "another"},
        {"hostname": None},
        {"process": {"pid": 4120, "creation_time": "2026-09-15T09:31:20Z"}},
        {"process": {"pid": 4120, "name": "notepad.exe"}},
        {"process": {"pid": 4120, "path": r"D:\elsewhere.exe"}},
        {"timestamp": "2026-09-16T10:00:00Z", "process": {"pid": 4120}},
    ],
)
def test_process_false_matches(make_event, patch):
    proc = {
        "pid": 4120,
        "name": "powershell.exe",
        "path": r"C:\Windows\powershell.exe",
        "creation_time": "2026-09-16T09:31:20Z",
    }
    a = make_event(process=proc)
    settings = {"process": proc, **patch}
    assert ProcessRule().evaluate(a, make_event("B", **settings)) == []


def test_windows_paths_and_command_tokens(make_event):
    a = make_event(process={"pid": 1, "command_line": 'powershell.exe -File "C:\\Temp Folder\\a.ps1"'})
    b = make_event("B", source="disk", file={"path": "c:/temp folder/a.ps1"})
    assert FileRule().evaluate(a, b)[0].rule == "command_line_file_path"
    c = make_event("C", source="disk", file={"path": "c:/temp folder/a.ps1.bak"})
    assert FileRule().evaluate(a, c) == []
    unrelated = make_event("D", source="disk", file={"path": "d:/other/a.ps1"})
    assert FileRule().evaluate(a, unrelated) == []


def test_file_hash_prefetch_ntfs(make_event):
    a = make_event(file={"path": r"C:\Temp\a.ps1", "sha256": "A" * 64})
    b = make_event(
        "B",
        file={"path": r"c:\temp\a.ps1", "sha256": "a" * 64},
        source="disk",
        source_artifact={"artifact_id": "mft", "kind": "$MFT"},
    )
    assert {r.rule for r in FileRule().evaluate(a, b)} == {
        "same_sha256",
        "same_file_path",
        "ntfs_artifact_support",
    }
    prefetch = make_event("C", file={"path": "ps.pf", "references": [r"C:\Temp\a.ps1"]})
    assert FileRule().evaluate(prefetch, b)[0].rule == "prefetch_reference"
    b.file.sha256 = "b" * 64
    assert FileRule().evaluate(a, b) == []


def test_network_socket_and_dns(make_event):
    net = {
        "src_ip": "192.168.0.15",
        "src_port": 50321,
        "dst_ip": "185.10.10.5",
        "dst_port": 443,
        "protocol": "TCP",
    }
    a, b = make_event(network=net), make_event("B", network=net, source="network")
    assert NetworkRule().evaluate(a, b)[0].rule == "same_socket_tuple"
    dns = make_event(
        "D",
        source="network",
        timestamp="2026-09-16T09:31:24Z",
        network={"src_ip": "192.168.0.15", "dns_query": "evil.example", "resolved_ips": ["185.10.10.5"]},
    )
    assert {r.rule for r in NetworkRule().evaluate(dns, b)} == {
        "dns_resolved_destination",
        "dns_preceded_connection",
    }
    late_dns = make_event(
        "L", source="network", timestamp="2026-09-16T09:31:26Z", network=dns.network.model_dump()
    )
    assert NetworkRule().evaluate(late_dns, b) == []


@pytest.mark.parametrize(
    "field,value", [("src_port", 50322), ("dst_port", 80), ("protocol", "UDP"), ("src_ip", "192.168.0.16")]
)
def test_network_tuple_conflicts(make_event, field, value):
    net = {
        "src_ip": "192.168.0.15",
        "src_port": 50321,
        "dst_ip": "185.10.10.5",
        "dst_port": 443,
        "protocol": "TCP",
    }
    assert (
        NetworkRule().evaluate(make_event(network=net), make_event("B", network={**net, field: value})) == []
    )


def test_score_cap_reason_preservation_and_order(make_event):
    proc = {
        "pid": 1,
        "name": "a",
        "path": "C:\\a.exe",
        "creation_time": "2026-09-16T09:00:00Z",
        "command_line": "a.exe",
    }
    a, b = make_event(process=proc), make_event("B", process=proc)
    engine = CorrelationEngine()
    results = engine.correlate([a, b])
    assert results[0].score == 100
    assert sum(r.score for r in results[0].reasons) > 100
    assert results == engine.correlate([b, a])
    assert all(reason.details and reason.evidence for reason in results[0].reasons)
    with pytest.raises(ValueError, match="score must"):
        Correlation(
            source_event="A", target_event="B", score=99, reasons=[Reason(rule="x", score=10, details="x")]
        )


def test_time_name_ip_and_basename_alone_do_not_link(make_event):
    pairs = [
        ({}, {}),
        ({"process": {"pid": 1, "name": "a.exe"}}, {"process": {"pid": 2, "name": "a.exe"}}),
        ({"network": {"dst_ip": "185.10.10.5"}}, {"network": {"dst_ip": "185.10.10.5"}}),
        ({"file": {"path": "C:\\a.ps1"}}, {"file": {"path": "D:\\a.ps1"}}),
    ]
    for a, b in pairs:
        assert CorrelationEngine().correlate([make_event(**a), make_event("B", **b)], min_score=1) == []


def test_empty_and_custom_rule_list(make_event):
    with pytest.raises(ValueError, match="empty"):
        CorrelationEngine().correlate([])
    assert CorrelationEngine(rules=[]).correlate([make_event(), make_event("B")]) == []
    with pytest.raises(TypeError, match="normalized Event"):
        CorrelationEngine().correlate([{"event_id": "raw"}])
