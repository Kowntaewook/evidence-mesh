import hashlib
import shutil
import subprocess
from pathlib import Path
from runpy import run_path

import pytest

from engine.collectors.network.pcap import PcapAdapter
from schemas.events import Event
from schemas.imports import ArtifactContext, RunStatus

_generator = run_path(str(Path(__file__).parents[1] / "scripts" / "generate_capture.py"))
dns, packet, sample_packets, write_capture = (
    _generator[name] for name in ("dns", "packet", "sample_packets", "write_capture")
)

FIXTURES = Path(__file__).parent / "fixtures" / "network"


@pytest.fixture
def adapter():
    return PcapAdapter(ArtifactContext(acquisition_id="capture-1", extracted_at="2026-09-16T09:35:00Z"))


@pytest.mark.parametrize("suffix", ["pcap", "pcapng"])
def test_actual_tshark_protocols_frames_flows_integrity(adapter, suffix):
    if not shutil.which("tshark"):
        pytest.skip("tshark is not installed")
    path = FIXTURES / f"sample.{suffix}"
    before = path.read_bytes()
    batch = adapter.load_file(path)
    run = batch.runs[0]
    assert run.status == RunStatus.SUCCESS, run.error
    assert run.row_count == 9 and run.event_count == 9
    assert run.artifact.sha256 == hashlib.sha256(before).hexdigest()
    assert run.artifact.size == len(before) and run.artifact.imported_at
    events = {e.type: e for e in batch.events}
    response = events["dns_response"]
    assert response.network.dns_response is True
    assert response.network.resolved_ips == ["203.0.113.20"]
    assert response.network.dns_query == "example.test"
    assert response.network.src_ip == "10.0.0.53"  # Preserve wire direction.
    tls = events["tls_client_hello"]
    assert tls.network.tls.sni == "example.test"
    assert tls.network.tls.server_port == 443 and tls.attributes["frame_number"] == 6
    assert tls.raw_reference.locator == "frame:6"
    assert events["http_request"].network.http.method == "GET"
    assert events["http_response"].network.http.status == 200
    flow = next(e for e in batch.events if e.type == "network_flow" and e.network.dst_port == 443)
    assert flow.network.packet_count == 4
    assert flow.network.byte_count == sum(len(data) for _, data in sample_packets()[2:6])
    assert flow.network.end_time > flow.timestamp
    assert flow.raw["frames"] == [3, 4, 5, 6]
    assert len([e for e in batch.events if e.type == "network_flow"]) == 4
    for event in batch.events:
        assert Event.model_validate_json(event.model_dump_json()) == event
        assert event.provenance[0].raw and event.provenance[0].source == "network"
    assert path.read_bytes() == before


@pytest.mark.parametrize("kind", ["dns", "tcp", "udp", "http", "tls"])
def test_protocol_optional_fields(adapter, tmp_path, kind):
    if not shutil.which("tshark"):
        pytest.skip("tshark is not installed")
    payload, protocol, port = b"", 6, 443
    if kind == "dns":
        payload, protocol, port = dns(), 17, 53
    elif kind == "udp":
        payload, protocol, port = b"plain data", 17, 9001
    elif kind == "http":
        payload, port = b"GET / HTTP/1.0\r\n\r\n", 80
    elif kind == "tls":
        # A TLS application record has no ClientHello or SNI.
        payload = bytes.fromhex("170303000400000000")
    path = tmp_path / (kind + ".pcapng")
    write_capture(path, [(1, packet("192.0.2.1", "192.0.2.2", 50000, port, payload, protocol))], True)
    batch = adapter.load_file(path)
    assert batch.runs[0].status == RunStatus.SUCCESS, batch.runs[0].error
    assert next(e for e in batch.events if e.type == "network_flow").network.packet_count == 1
    if kind == "dns":
        assert next(e for e in batch.events if e.type == "dns_query").network.resolved_ips == []
    elif kind == "http":
        assert next(e for e in batch.events if e.type == "http_request").network.http.host is None
    elif kind == "tls":
        tls = next(e for e in batch.events if e.type == "tls_record").network.tls
        assert tls.sni is None and tls.client_ip is None


@pytest.mark.parametrize("suffix", ["pcap", "pcapng"])
@pytest.mark.parametrize("content", [b"not a capture", b"", b"\xd4\xc3\xb2\xa1"])
def test_malformed_captures(adapter, tmp_path, suffix, content):
    if not shutil.which("tshark"):
        pytest.skip("tshark is not installed")
    path = tmp_path / ("bad." + suffix)
    path.write_bytes(content)
    batch = adapter.load_file(path)
    assert batch.runs[0].status == RunStatus.FAILED
    assert batch.runs[0].error and not batch.events


def test_missing_capture_and_decoder_are_distinct(adapter, tmp_path, monkeypatch):
    assert adapter.load_file(tmp_path / "missing.pcap").runs[0].status == RunStatus.FAILED
    monkeypatch.setattr("engine.collectors.network.pcap.shutil.which", lambda _: None)
    batch = adapter.load_file(FIXTURES / "sample.pcap")
    assert batch.runs[0].status == RunStatus.UNAVAILABLE and batch.runs[0].error


@pytest.mark.parametrize("failure", ["timeout", "exit", "schema"])
def test_subprocess_failure_is_recorded_with_safe_arguments(adapter, monkeypatch, failure):
    def run(command, *, stdout, stderr, timeout, check):
        assert isinstance(command, list) and "-r" in command and "-n" in command
        assert timeout == 180 and check is False
        stderr.write("decoder detail")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, timeout)
        if failure == "schema":
            stdout.write("wrong\tfields\n1\t2\n")
        return subprocess.CompletedProcess(command, 2 if failure == "exit" else 0)

    monkeypatch.setattr("engine.collectors.network.pcap.subprocess.run", run)
    adapter.executable = "/explicit/tshark"
    batch = adapter.load_file(FIXTURES / "sample.pcap")
    assert batch.runs[0].status == RunStatus.FAILED and not batch.events
    assert batch.runs[0].stderr == "decoder detail" and batch.runs[0].error


def test_path_with_shell_metacharacters_is_literal(adapter, tmp_path):
    if not shutil.which("tshark"):
        pytest.skip("tshark is not installed")
    path = tmp_path / "capture $(touch SHOULD_NOT_EXIST); 'quoted'.pcap"
    path.write_bytes((FIXTURES / "sample.pcap").read_bytes())
    batch = adapter.load_file(path)
    assert batch.runs[0].status == RunStatus.SUCCESS
    assert str(path) in batch.runs[0].command
    assert not (tmp_path / "SHOULD_NOT_EXIST").exists()
