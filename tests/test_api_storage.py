import sqlite3
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from engine.storage import SQLiteRepository
from engine.storage.base import ConflictError
from schemas.results import CaseCreate


def create(client):
    response = client.post("/cases", json={"name": "Test Investigation"})
    assert response.status_code == 201
    return response.json()["case_id"]


def test_api_workflow(client, sample):
    assert client.get("/health").json()["status"] == "ok"
    case_id = create(client)
    base = f"/cases/{case_id}"
    assert (
        client.post(base + "/events", json=[e.model_dump(mode="json") for e in sample]).json()["imported"]
        == 15
    )
    assert client.get(base + "/correlations").status_code == 409
    result = client.post(base + "/correlate", json={"root_event_id": "MEM-PS"})
    assert result.status_code == 200 and result.json()["status"] == "completed"
    query = {"root_event_id": "MEM-PS"}
    timeline = client.get(base + "/timeline", params=query).json()["events"]
    assert len(timeline) == 9 and not any(e["event_id"].startswith("NOISE") for e in timeline)
    timestamps = [datetime.fromisoformat(e["timestamp"]) for e in timeline]
    assert timestamps == sorted(timestamps)
    graph = client.get(base + "/graph", params=query).json()
    assert graph["root_event_id"] == "MEM-PS" and len(graph["edges"]) > 0
    correlations = client.get(base + "/correlations", params=query).json()
    assert all(edge["reasons"] for edge in correlations)
    assert client.get(base).json()["event_count"] == 15
    assert len(client.get("/cases").json()) == 1
    assert len(client.get(base + "/events", params={"source": "network"}).json()) == 4
    assert len(client.get(base + "/events", params={"pid": 4120}).json()) == 3
    assert client.get(base + "/graph", params={"root_event_id": "missing"}).status_code == 404


def test_validation_missing_cases_empty_analysis(client, make_event):
    assert client.get("/cases/missing").status_code == 404
    assert client.get("/cases/missing/events").status_code == 404
    case_id = create(client)
    base = f"/cases/{case_id}"
    assert client.post(base + "/correlate").status_code == 422
    assert client.post(base + "/events", json=[]).status_code == 422
    assert client.post(base + "/events", json=[{"event_id": "bad"}]).status_code == 422
    assert client.post(base + "/correlate", json={"min_score": 101}).status_code == 422
    event = make_event().model_dump(mode="json")
    client.post(base + "/events", json=[event])
    result = client.post(base + "/correlate")
    assert result.json()["status"] == "no_matches"
    assert result.json()["correlation_count"] == 0


def test_duplicate_batch_atomic_and_analysis_invalidation(client, sample, make_event):
    base = f"/cases/{create(client)}"
    client.post(base + "/events", json=[e.model_dump(mode="json") for e in sample])
    client.post(base + "/correlate")
    batch = [make_event("NEW").model_dump(mode="json"), sample[0].model_dump(mode="json")]
    assert client.post(base + "/events", json=batch).status_code == 409
    assert len(client.get(base + "/events").json()) == 15
    assert client.get(base + "/correlations").status_code == 200
    assert client.post(base + "/events", json=batch[:1]).status_code == 201
    assert client.get(base + "/correlations").status_code == 409


def test_case_isolation_restart_and_reason_persistence(tmp_path, sample):
    path = tmp_path / "persist.sqlite3"
    with TestClient(create_app(path)) as client:
        a, b = create(client), create(client)
        for case_id in (a, b):
            client.post(f"/cases/{case_id}/events", json=[e.model_dump(mode="json") for e in sample])
        result = client.post(f"/cases/{a}/correlate").json()
        assert client.get(f"/cases/{b}/correlations").status_code == 409
    with TestClient(create_app(path)) as client:
        persisted = client.get(f"/cases/{a}/correlations").json()
        assert {str(edge) for edge in persisted} == {str(edge) for edge in result["correlations"]}
        assert client.get(f"/cases/{a}").json()["analysis_revision"] == 1


def test_analysis_revision_conflict(tmp_path, make_event):
    repo = SQLiteRepository(tmp_path / "conflict.sqlite3")
    case = repo.create_case(CaseCreate(name="case"))
    repo.add_events(case.case_id, [make_event()])
    with pytest.raises(ConflictError, match="changed"):
        repo.save_correlations(case.case_id, [], revision=0)


def test_sample_endpoint_and_openapi(client):
    response = client.post("/samples/load")
    assert response.status_code == 201 and response.json()["event_count"] == 15
    schema = client.get("/openapi.json").json()
    expected = {
        "/health",
        "/cases",
        "/cases/{case_id}",
        "/cases/{case_id}/events",
        "/cases/{case_id}/correlate",
        "/cases/{case_id}/correlations",
        "/cases/{case_id}/graph",
        "/cases/{case_id}/timeline",
    }
    assert expected <= schema["paths"].keys()


def test_future_database_version_untouched(tmp_path):
    path = tmp_path / "future.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=2")
    before = path.read_bytes()
    with pytest.raises(ValueError, match="Unsupported database"):
        SQLiteRepository(path)
    assert path.read_bytes() == before
