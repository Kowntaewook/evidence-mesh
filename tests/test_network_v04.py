"""Offline HTTP reassembly and TLS with/without explicitly supplied key material."""

import hashlib
import shutil
import ssl
from pathlib import Path
from runpy import run_path

import pytest

from engine.collectors.disk.artifacts import DiskArtifactAdapter
from engine.collectors.network.pcap import PcapAdapter
from schemas.imports import ArtifactContext, RunStatus

FIXTURES = Path(__file__).parent / "fixtures" / "network"
GENERATOR = run_path(str(Path(__file__).parents[1] / "scripts" / "generate_capture.py"))
packet, write_capture = (GENERATOR[name] for name in ("packet", "write_capture"))


def context(**options):
    return ArtifactContext(acquisition_id="network-v04", extracted_at="2026-09-16T09:35:00Z", **options)


@pytest.mark.parametrize("chunked", [False, True])
@pytest.mark.parametrize("is_request", [False, True])
@pytest.mark.parametrize("pcapng", [False, True])
def test_actual_http_request_response_body_reassembly_and_hash(tmp_path, chunked, is_request, pcapng):
    if not shutil.which("tshark"):
        pytest.skip("tshark is not installed")
    body = b"inert HTTP download\x00\xff\n"
    prefix = b"POST /body HTTP/1.1\r\nHost: example.test\r\n" if is_request else b"HTTP/1.1 200 OK\r\n"
    if chunked:
        encoded = (
            b"5\r\n" + body[:5] + b"\r\n" + f"{len(body) - 5:x}\r\n".encode() + body[5:] + b"\r\n0\r\n\r\n"
        )
        payload = (
            prefix + b"Transfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n" + encoded
        )
    else:
        payload = (
            prefix
            + f"Content-Length: {len(body)}\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
            + body
        )
    source, target, sport, dport = (
        ("192.0.2.1", "192.0.2.2", 50000, 80) if is_request else ("192.0.2.2", "192.0.2.1", 80, 50000)
    )
    split = len(payload) - 9
    packets = [
        (1, packet(source, target, sport, dport, payload[:split], sequence=1)),
        (2, packet(source, target, sport, dport, payload[split:], sequence=split + 1)),
    ]
    path = tmp_path / ("body.pcapng" if pcapng else "body.pcap")
    write_capture(path, packets, pcapng)
    original = path.read_bytes()
    batch = PcapAdapter(context(), workspace=tmp_path / "work").load_file(path)
    assert batch.runs[0].status == RunStatus.SUCCESS, batch.runs[0].error
    event = next(event for event in batch.events if event.network.http)
    recovered = event.network.http
    assert recovered.body_sha256 == hashlib.sha256(body).hexdigest(), batch.runs[0].warnings
    assert Path(recovered.recovered_path).read_bytes() == body
    assert recovered.body_size == len(body)
    assert recovered.decrypted_with_supplied_key is False
    assert event.file.sha256 == recovered.body_sha256
    assert event.provenance[0].source_artifact.sha256 == hashlib.sha256(original).hexdigest()
    assert path.read_bytes() == original
    assert "http.file_data" not in event.raw
    disk = tmp_path / "download.bin"
    disk.write_bytes(body)
    disk_event = (
        DiskArtifactAdapter(context(logical_path="C:\\Downloads\\body.bin")).load_file(disk, "file").events[0]
    )
    from engine.correlation.file import FileRule

    reasons = FileRule().evaluate(event, disk_event)
    assert any(reason.rule == "same_sha256" for reason in reasons)


def tls_capture(path, keylog):
    """Real TLS 1.2 handshake over MemoryBIO, no socket or external service."""
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(
        FIXTURES / "tls-v04-certificate.pem", FIXTURES / "tls-v04-public-test-key.pem"
    )
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    client_context.keylog_filename = str(keylog)
    for settings in (client_context, server_context):
        settings.minimum_version = settings.maximum_version = ssl.TLSVersion.TLSv1_2
        settings.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    client_in, client_out, server_in, server_out = [ssl.MemoryBIO() for _ in range(4)]
    client = client_context.wrap_bio(client_in, client_out, server_hostname="evidencemesh-fixture.invalid")
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    packets = [
        (0, packet("192.0.2.1", "192.0.2.2", 50000, 443, flags=2, sequence=0)),
        (0.01, packet("192.0.2.2", "192.0.2.1", 443, 50000, flags=0x12, sequence=0)),
        (0.02, packet("192.0.2.1", "192.0.2.2", 50000, 443, flags=0x10, sequence=1)),
    ]
    sequences = [1, 1]

    def transfer(outgoing, incoming, direction):
        data = outgoing.read()
        if not data:
            return
        incoming.write(data)
        endpoints = (
            ("192.0.2.1", "192.0.2.2", 50000, 443)
            if not direction
            else ("192.0.2.2", "192.0.2.1", 443, 50000)
        )
        packets.append((len(packets) / 10, packet(*endpoints, data, sequence=sequences[direction])))
        sequences[direction] += len(data)

    done = [False, False]
    for _ in range(10):
        for index, session in enumerate((client, server)):
            try:
                session.do_handshake()
                done[index] = True
            except ssl.SSLWantReadError:
                pass
            transfer(client_out, server_in, 0)
            transfer(server_out, client_in, 1)
        if all(done):
            break
    assert all(done)
    request = b"GET /secret HTTP/1.1\r\nHost: evidencemesh-fixture.invalid\r\n\r\n"
    client.write(request)
    transfer(client_out, server_in, 0)
    assert server.read() == request
    body = b"inert encrypted evidence\n"
    server.write(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode()
        + body
    )
    transfer(server_out, client_in, 1)
    write_capture(path, packets, pcapng=True)
    return body


def test_actual_tls_only_decrypts_with_supplied_key_material(tmp_path):
    if not shutil.which("tshark"):
        pytest.skip("tshark is not installed")
    path, keylog = tmp_path / "encrypted.pcapng", tmp_path / "supplied-secrets.log"
    body = tls_capture(path, keylog)
    original_keylog = keylog.read_bytes()
    without = PcapAdapter(context(), workspace=tmp_path / "without").load_file(path)
    assert without.runs[0].status == RunStatus.SUCCESS, without.runs[0].error
    assert not any(event.network.http for event in without.events)
    assert all(
        event.network.tls.decryption == "metadata_only" for event in without.events if event.network.tls
    )
    assert not any("tls.keylog_file:" in argument for argument in without.runs[0].command)
    supplied = PcapAdapter(context(tls_keylog_file=str(keylog)), workspace=tmp_path / "with").load_file(path)
    assert supplied.runs[0].status == RunStatus.SUCCESS, supplied.runs[0].error
    assert f"tls.keylog_file:{keylog}" in supplied.runs[0].command
    responses = [event for event in supplied.events if event.network.http and event.network.http.status]
    assert len(responses) == 1
    assert responses[0].network.http.decrypted_with_supplied_key is True
    assert Path(responses[0].network.http.recovered_path).read_bytes() == body
    assert any(
        event.network.tls and event.network.tls.decryption == "decrypted_with_supplied_key"
        for event in supplied.events
    )
    assert keylog.read_bytes() == original_keylog
    missing = PcapAdapter(context(tls_keylog_file=str(tmp_path / "absent"))).load_file(path)
    assert missing.runs[0].status == RunStatus.FAILED
    assert not missing.events
