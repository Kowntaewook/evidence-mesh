from engine.graph import build_graph
from engine.storage import SQLiteRepository
from engine.storage.views import bounded_graph, event_page
from schemas.results import CaseCreate, Correlation, Reason


def test_server_event_pages_search_source_counts_and_boundaries(client, sample):
    case = client.post("/samples/load").json()["case_id"]
    base = f"/cases/{case}/event-page"
    page = client.get(base, params={"limit": 2}).json()
    assert page["total"] == 15 and len(page["events"]) == 2
    assert sum(page["counts"]["sources"].values()) == 15
    next_page = client.get(base, params={"limit": 2, "offset": 2}).json()
    assert not (
        {event["event_id"] for event in page["events"]} & {event["event_id"] for event in next_page["events"]}
    )
    search = client.get(base, params={"query": "MEM-PS"}).json()
    assert any(event["event_id"] == "MEM-PS" for event in search["events"])
    files = client.get(base, params={"view": "files"}).json()
    assert files["total"] and all(event["source"] == "disk" and event["file"] for event in files["events"])
    assert client.get(base, params={"limit": 501}).status_code == 422
    assert client.get(base, params={"view": "file' OR 1=1"}).status_code == 422
    assert client.get(base, params={"query": "%' OR 1=1 --"}).json()["total"] == 0
    assert client.get("/cases/missing/event-page").status_code == 404


def test_graph_depth_score_type_and_limits_are_actual_server_bounds(tmp_path, make_event, monkeypatch):
    repository = SQLiteRepository(tmp_path / "graph.sqlite3")
    case = repository.create_case(CaseCreate(name="Bounded graph"))
    events = [make_event(str(index), process={"pid": index, "name": f"p{index}.exe"}) for index in range(20)]
    repository.add_events(case.case_id, events)
    edges = [
        Correlation(
            source_event=str(index),
            target_event=str(index + 1),
            score=60,
            reasons=[Reason(rule="same_process_instance", score=60, details="synthetic adjacency")],
        )
        for index in range(19)
    ]
    repository.save_correlations(case.case_id, edges, 1)
    # If either legacy whole-case load path is used, this test fails.
    monkeypatch.setattr(
        repository, "events", lambda *_: (_ for _ in ()).throw(AssertionError("Unbounded load"))
    )
    monkeypatch.setattr(
        repository, "correlations", lambda *_: (_ for _ in ()).throw(AssertionError("Unbounded load"))
    )
    one = bounded_graph(repository, case.case_id, "0", depth=1, limit=100)
    assert {event.event_id for event in one.supporting_events} == {"0", "1"}
    two = bounded_graph(repository, case.case_id, "0", depth=2, limit=100)
    assert {event.event_id for event in two.supporting_events} == {"0", "1", "2"}
    high = bounded_graph(repository, case.case_id, "0", depth=8, limit=100, min_score=61)
    assert {event.event_id for event in high.supporting_events} == {"0"}
    filtered = bounded_graph(repository, case.case_id, "0", depth=2, limit=100, node_types=["Process"])
    assert filtered.nodes and all(node.kind == "Process" for node in filtered.nodes)
    capped = bounded_graph(repository, case.case_id, "0", depth=8, limit=3)
    assert len(capped.nodes) == 3 and capped.truncated
    assert any(node.id == "event:0" for node in capped.nodes)
    assert all(
        edge.source in {node.id for node in capped.nodes}
        and edge.target in {node.id for node in capped.nodes}
        for edge in capped.edges
    )
    reference = build_graph(events[:3], edges[:2], "0")
    assert {node.id for node in two.nodes} == {node.id for node in reference.nodes}


def test_graph_api_and_correlation_response_limit(client):
    case = client.post("/samples/load").json()["case_id"]
    base = f"/cases/{case}"
    assert client.get(base + "/graph", params={"limit": 5}).status_code == 409
    analysis = client.post(base + "/correlate", json={"root_event_id": "MEM-PS", "result_limit": 1}).json()
    assert len(analysis["correlations"]) == 1 and analysis["correlation_count"] > 1 and analysis["truncated"]
    graph = client.get(base + "/graph", params={"root_event_id": "MEM-PS", "depth": 0, "limit": 5}).json()
    assert all(node["event_ids"] == ["MEM-PS"] for node in graph["nodes"])
    assert client.get(base + "/graph", params={"limit": 2, "node_types": "Unknown"}).status_code == 422
    assert client.get(base + "/graph", params={"root_event_id": "missing", "limit": 5}).status_code == 404


def test_100k_event_page_deserializes_only_requested_rows(tmp_path, make_event, monkeypatch):
    import json

    from schemas.events import Event

    repository = SQLiteRepository(tmp_path / "large.sqlite3")
    case = repository.create_case(CaseCreate(name="100k page"))
    template = make_event(source="disk", file={"path": "C:\\fixture.txt"}).model_dump(mode="json")
    # Bulk-load valid generated records without a quadratic fixture constructor.
    with repository.connection() as db:

        def rows():
            for index in range(100000):
                event_id = f"E-{index:06}"
                yield (
                    case.case_id,
                    event_id,
                    template["timestamp"],
                    "disk",
                    json.dumps({**template, "event_id": event_id}),
                    "observation",
                )

        db.executemany(
            "INSERT INTO events(case_id,event_id,timestamp,source,data,event_type) VALUES(?,?,?,?,?,?)",
            rows(),
        )
        db.execute("UPDATE cases SET revision=1 WHERE case_id=?", (case.case_id,))
    original = Event.model_validate_json
    decoded = []

    def counted(value, **kwargs):
        decoded.append(1)
        return original(value, **kwargs)

    monkeypatch.setattr(Event, "model_validate_json", counted)
    result = event_page(repository, case.case_id, view="files", offset=99900, limit=100)
    assert len(result["events"]) == 100 and result["total"] == 100000
    assert result["events"][0].event_id == "E-099900"
    assert len(decoded) == 100
