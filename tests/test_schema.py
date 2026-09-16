from copy import deepcopy

import pytest
from pydantic import ValidationError

from engine.normalization import normalize_event, normalize_events
from schemas.events import Event


@pytest.mark.parametrize(
    "patch",
    [
        {"event_id": ""},
        {"timestamp": "2026-09-16T00:00:00"},
        {"source": "unknown"},
        {"process": {"pid": -1}},
        {"process": {"pid": True}},
        {"process": {"pid": "123"}},
        {"network": {"dst_port": 65536}},
        {"network": {"dst_ip": "not-an-ip"}},
        {"file": {"sha256": "wrong"}},
        {"schema_version": "2.0"},
        {"misspelled": 1},
        {
            "raw_reference": {"artifact_id": "a", "locator": "/1"},
            "source_artifact": {"artifact_id": "b", "kind": "json"},
        },
    ],
)
def test_reject_invalid_fields(make_event, patch):
    with pytest.raises(ValidationError):
        make_event(**patch)


def test_required_fields(make_event):
    record = make_event().model_dump()
    for field in ("event_id", "timestamp", "source", "type"):
        value = record.copy()
        value.pop(field)
        with pytest.raises(ValidationError):
            Event.model_validate(value)


def test_normalization_preserves_original_and_reference():
    record = {
        "event_id": "a",
        "timestamp": "2026-09-16T18:31:25+09:00",
        "source": "memory",
        "type": "process_start",
        "hostname": "HOST-01",
        "process": {"pid": 4120},
        "attributes": {"command_line": "powershell.exe -File a.ps1"},
        "raw": {"original": "unchanged"},
        "network": {"protocol": "tcp", "dns_query": "EVIL.EXAMPLE.", "dst_ip": "2001:0db8::1"},
    }
    original = deepcopy(record)
    normalized = normalize_event(record)
    assert record == original
    assert normalized.timestamp.isoformat() == "2026-09-16T09:31:25+00:00"
    assert normalized.hostname == "host-01"
    assert normalized.process.command_line == record["attributes"]["command_line"]
    assert normalized.network.protocol == "TCP"
    assert normalized.network.dns_query == "evil.example"
    assert normalized.network.dst_ip == "2001:db8::1"
    assert normalized.raw == record["raw"]
    assert normalize_event(normalized) == normalized


def test_empty_and_duplicate_batches(make_event):
    with pytest.raises(ValueError, match="No events"):
        normalize_events([])
    with pytest.raises(ValueError, match="Duplicate"):
        normalize_events([make_event(), make_event()])
