import contextlib
import hashlib
import io
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from engine.collectors.disk.artifacts import DiskArtifactAdapter
from engine.collectors.memory.extended import MemoryImportAdapter
from engine.collectors.network.pcap import FIELDS, PcapAdapter
from engine.parsers.eventlog import EventLogParser
from engine.parsers.ntfs import MFTParser, USNParser
from engine.parsers.pcap import PCAPParser
from engine.parsers.prefetch import PrefetchParser
from schemas.imports import ArtifactContext

ROOT = Path(__file__).parents[1]
CONTEXT = ArtifactContext(
    acquisition_id="tool-compatibility", extracted_at="2026-09-16T09:35:00Z", timezone="UTC"
)


def test_actual_volatility_json_renderer_compatibility(tmp_path):
    pytest.importorskip("volatility3")
    from volatility3.cli.text_renderer import JsonRenderer
    from volatility3.framework import renderers
    from volatility3.framework.renderers import format_hints

    columns = [
        ("PID", int),
        ("PPID", int),
        ("ImageFileName", str),
        ("Offset(V)", format_hints.Hex),
        ("CreateTime", datetime),
        ("ExitTime", datetime),
    ]
    missing = renderers.NotApplicableValue()
    rows = [
        (
            0,
            (
                100,
                0,
                "explorer.exe",
                format_hints.Hex(0xFFFF800000000123),
                datetime(2026, 9, 16, 9, tzinfo=UTC),
                missing,
            ),
        ),
        (
            1,
            (
                200,
                100,
                "powershell.exe",
                format_hints.Hex(0xFFFF800000000321),
                datetime(2026, 9, 16, 9, 1, tzinfo=UTC),
                missing,
            ),
        ),
    ]
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        JsonRenderer().render(renderers.TreeGrid(columns, iter(rows)))
    path = tmp_path / "pslist.json"
    path.write_text(output.getvalue())
    emitted = json.loads(output.getvalue())
    assert emitted[0]["__children"][0]["PID"] == 200 and emitted[0]["ExitTime"] is None
    batch = MemoryImportAdapter(CONTEXT).load_exports([("windows.pslist.PsList", path)])
    assert batch.runs[0].status == "SUCCESS", batch.runs[0].error
    assert len(batch.events) == 2
    assert batch.events[1].process.parent_instance_id == batch.events[0].process.instance_id
    assert batch.events[0].provenance[0].raw["Offset(V)"] == 0xFFFF800000000123


@pytest.mark.parametrize(
    "name,kind,count",
    [
        ("amcache-new.hve", "amcache", 222),
        ("amcache-old.hve", "amcache", 69),
        ("Security.evtx", "evtx", 759),
        ("TestLogX.evtx", "evtx", 5),
    ],
)
def test_public_binary_artifact_compatibility_when_available(name, kind, count):
    path = ROOT / "data" / "compatibility" / name
    if not path.exists():
        pytest.skip("Optional public compatibility artifacts are not distributed with this project")
    sources = json.loads((path.parent / "sources.json").read_text())
    entry = next(item for item in sources if item["file"] == name)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    assert before == entry["sha256"]
    batch = DiskArtifactAdapter(CONTEXT).load_file(path, kind)
    assert batch.runs[0].status == "SUCCESS", batch.runs[0].error
    assert len(batch.events) == count
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


@pytest.mark.parametrize(
    "parser,path",
    [
        (MFTParser, "disk/mft-record.bin"),
        (USNParser, "disk/usn-v2.bin"),
        (PrefetchParser, "disk/sample-v30.pf"),
        (EventLogParser, "disk/event.xml"),
        (PCAPParser, "network/sample.pcapng"),
    ],
)
def test_configured_parser_protocol_facades(parser, path):
    if parser is PCAPParser and not shutil.which("tshark"):
        pytest.skip("tshark is not installed")
    result = parser(CONTEXT).parse(ROOT / "tests/fixtures" / path)
    assert result and all(event["provenance"] for event in result)


@pytest.mark.parametrize(
    "protocol,fields",
    [
        ("DNS", {"dns.id": "1", "dns.qry.name": "example.test", "dns.a": "invalid-ip"}),
        ("TCP", {"tcp.srcport": "70000"}),
        ("UDP", {"tcp.srcport": "", "tcp.dstport": "", "udp.srcport": "70000", "udp.dstport": "53"}),
        ("HTTP", {"http.request.method": "GET", "http.response.code": "999"}),
        ("TLS", {"tls.handshake.extensions_server_name": "example.test", "ip.src": "invalid-ip"}),
    ],
)
def test_malformed_decoded_protocol_fields_are_not_accepted(protocol, fields):
    from engine.ingestion.evidence import EvidenceReader
    from schemas.events import Source

    path = ROOT / "tests/fixtures/network/sample.pcap"
    reader = EvidenceReader(path, Source.NETWORK, "PCAP", CONTEXT, "TsharkAdapter")
    row = dict.fromkeys(FIELDS, "")
    row.update(
        {
            "frame.number": "1",
            "frame.time_epoch": "1",
            "frame.len": "100",
            "ip.src": "192.0.2.1",
            "ip.dst": "192.0.2.2",
            "tcp.srcport": "1234",
            "tcp.dstport": "443",
            **fields,
        }
    )
    with pytest.raises(ValueError):
        PcapAdapter(CONTEXT)._packet(reader, row, {})


def test_many_connections_to_one_resolver_do_not_generate_all_pairs(make_event):
    from engine.correlation.index import EventIndex

    events = [
        make_event(
            str(i),
            source="network",
            hostname=None,
            network={
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.53",
                "src_port": 10000 + i,
                "dst_port": 53,
                "protocol": "UDP",
                "dns_query": f"{i}.example.test",
                "dns_id": str(i),
            },
        )
        for i in range(2000)
    ]
    assert EventIndex(events).pairs() == []
