"""Bounded event pages and adjacency queries; no full-case event deserialization."""

from engine.graph import build_graph
from engine.storage.base import AnalysisRequiredError, NotFoundError
from schemas.events import Event
from schemas.results import Correlation, NodeKind


def object_field(name):
    return f"json_type(data,'$.{name}')='object'"


VIEW_FILTERS = {
    "case": "1",
    "evidence": "1",
    "timeline": "1",
    "processes": "source='memory' AND " + object_field("process"),
    "memory-network": "source='memory' AND " + object_field("network"),
    "dlls": "event_type='module_load'",
    "handles": object_field("handle") + " OR event_type='file_object_observation'",
    "regions": object_field("memory_region"),
    "services": object_field("service"),
    "modules": "("
    + object_field("module")
    + " AND json_type(data,'$.process')!='object') OR "
    + object_field("driver")
    + " OR "
    + object_field("callback"),
    "memory-registry": "source='memory' AND " + object_field("registry"),
    "files": "source='disk' AND " + object_field("file"),
    "mft": "json_extract(data,'$.source_artifact.kind')='$MFT'",
    "usn": "json_extract(data,'$.source_artifact.kind')='$UsnJrnl'",
    "prefetch": "event_type='prefetch' OR json_extract(data,'$.source_artifact.kind')='Prefetch'",
    "event-logs": object_field("event_log"),
    "amcache": "source='disk' AND json_extract(data,'$.registry.artifact')='amcache'",
    "connections": "source='network' AND "
    + object_field("network")
    + " AND json_extract(data,'$.network.dns_query') IS NULL",
    "dns": "json_extract(data,'$.network.dns_query') IS NOT NULL",
    "http": "event_type LIKE 'http%'",
    "tls": "event_type LIKE 'tls%'",
}
COUNTS_CACHE = {}


def event_page(
    repository, case_id, view="evidence", query="", limit=100, offset=0, source=None, category=None
):
    if view not in VIEW_FILTERS or not 1 <= limit <= 500 or offset < 0:
        raise ValueError("Invalid evidence page parameters")
    where, values = ["case_id=?", f"({VIEW_FILTERS[view]})"], [case_id]
    if source:
        if source not in {"memory", "disk", "network"}:
            raise ValueError("Invalid evidence source")
        where.append("source=?")
        values.append(source)
    if category:
        if category not in {"process", "file", "registry", "service", "network", "dns", "connection"}:
            raise ValueError("Invalid timeline category")
        clause = object_field(category)
        if category == "dns":
            clause = VIEW_FILTERS["dns"]
        elif category == "connection":
            clause = object_field("network") + " AND json_extract(data,'$.network.dns_query') IS NULL"
        where.append(f"({clause})")
    if query:
        if len(query) > 500:
            raise ValueError("Search query exceeds 500 characters")
        where.append("instr(lower(data),lower(?))>0")
        values.append(query)
    with repository.connection() as db:
        db.execute("BEGIN")
        case = repository._case(db, case_id)
        # Prefer process observations when the case contains them, matching the
        # established UI's fallback for legacy memory imports.
        process_observations = db.execute(
            "SELECT 1 FROM events WHERE case_id=? AND source='memory' AND event_type IN "
            "('process_start','process_observation','process') LIMIT 1",
            (case_id,),
        ).fetchone()
        if view == "processes" and process_observations:
            where.append("event_type IN ('process_start','process_observation','process')")
        predicate = " AND ".join(where)
        total = db.execute("SELECT count(*) FROM events WHERE " + predicate, values).fetchone()[0]
        rows = db.execute(
            "SELECT data FROM events WHERE " + predicate + " ORDER BY timestamp,event_id LIMIT ? OFFSET ?",
            (*values, limit, offset),
        ).fetchall()
        cache_key = (repository.path, case_id, case.revision)
        counts = COUNTS_CACHE.get(cache_key)
        if counts is None:
            names = list(VIEW_FILTERS)
            filters = dict(VIEW_FILTERS)
            if process_observations:
                filters["processes"] += " AND event_type IN ('process_start','process_observation','process')"
            aggregates = ",".join(
                f"coalesce(sum(CASE WHEN ({filters[name]}) THEN 1 ELSE 0 END),0)" for name in names
            )
            counts = dict(
                zip(
                    names,
                    db.execute(
                        "SELECT " + aggregates + " FROM events WHERE case_id=?", (case_id,)
                    ).fetchone(),
                    strict=True,
                )
            )
            counts["sources"] = dict(
                db.execute(
                    "SELECT source,count(*) FROM events WHERE case_id=? GROUP BY source", (case_id,)
                ).fetchall()
            )
            if len(COUNTS_CACHE) >= 128:
                COUNTS_CACHE.pop(next(iter(COUNTS_CACHE)))
            COUNTS_CACHE[cache_key] = counts
    return {
        "events": [Event.model_validate_json(row[0]) for row in rows],
        "total": total,
        "offset": offset,
        "limit": limit,
        "counts": counts,
        "revision": case.revision,
    }


def bounded_graph(repository, case_id, root, depth=2, limit=500, min_score=0, node_types=None):
    if not 0 <= depth <= 8 or not 1 <= limit <= 2000 or not 0 <= min_score <= 100:
        raise ValueError("Invalid graph bounds")
    kinds = set(node_types or [])
    if kinds - {kind.value for kind in NodeKind}:
        raise ValueError("Unknown graph node type")
    with repository.connection() as db:
        db.execute("BEGIN")
        case = repository._case(db, case_id)
        if case.analysis_revision != case.revision:
            raise AnalysisRequiredError("No current analysis; run correlation after importing evidence")
        if (
            root is not None
            and not db.execute(
                "SELECT 1 FROM events WHERE case_id=? AND event_id=?", (case_id, root)
            ).fetchone()
        ):
            raise NotFoundError(f"Root event not found: {root}")
        if root:
            ids, frontier, collected, truncated = {root}, {root}, {}, False
            for _ in range(depth):
                if not frontier:
                    break
                next_frontier = set()
                ordered = sorted(frontier)
                for start in range(0, len(ordered), 200):
                    batch = ordered[start : start + 200]
                    marks = ",".join("?" for _ in batch)
                    cap = limit * 8
                    rows = db.execute(
                        f"SELECT data FROM correlations WHERE case_id=? AND (source_event IN ({marks}) "
                        f"OR target_event IN ({marks})) AND json_extract(data,'$.score')>=? "
                        "ORDER BY json_extract(data,'$.score') DESC,source_event,target_event LIMIT ?",
                        (case_id, *batch, *batch, min_score, cap + 1),
                    ).fetchall()
                    truncated |= len(rows) > cap
                    for row in rows[:cap]:
                        edge = Correlation.model_validate_json(row[0])
                        endpoints = {edge.source_event, edge.target_event}
                        missing = endpoints - ids
                        if len(ids) + len(missing) > limit:
                            truncated = True
                            continue
                        ids.update(missing)
                        next_frontier.update(missing)
                        collected[(edge.source_event, edge.target_event)] = edge
                frontier = next_frontier
            correlations = list(collected.values())
            ids = sorted(ids)
            marks = ",".join("?" for _ in ids)
            rows = db.execute(
                f"SELECT data FROM events WHERE case_id=? AND event_id IN ({marks}) "
                "ORDER BY timestamp,event_id",
                (case_id, *ids),
            ).fetchall()
            truncated |= bool(frontier) and depth > 0
        else:
            rows = db.execute(
                "SELECT data FROM events WHERE case_id=? ORDER BY timestamp,event_id LIMIT ?",
                (case_id, limit),
            ).fetchall()
            ids = [Event.model_validate_json(row[0]).event_id for row in rows]
            correlations, truncated = [], case.event_count > len(rows)
            if ids:
                marks = ",".join("?" for _ in ids)
                edge_rows = db.execute(
                    f"SELECT data FROM correlations WHERE case_id=? AND source_event IN ({marks}) "
                    f"AND target_event IN ({marks}) AND json_extract(data,'$.score')>=? LIMIT ?",
                    (case_id, *ids, *ids, min_score, limit * 8 + 1),
                ).fetchall()
                correlations = [Correlation.model_validate_json(row[0]) for row in edge_rows[: limit * 8]]
                truncated |= len(edge_rows) > limit * 8
        events = [Event.model_validate_json(row[0]) for row in rows]
    graph = build_graph(events, correlations, root)
    nodes = [node for node in graph.nodes if not kinds or node.kind.value in kinds]
    nodes.sort(key=lambda node: (node.id != f"event:{root}", node.id))
    truncated |= len(nodes) > limit
    graph.nodes = nodes[:limit]
    included = {node.id for node in graph.nodes}
    graph.edges = [edge for edge in graph.edges if edge.source in included and edge.target in included][
        : limit * 8
    ]
    graph.truncated = truncated
    needed = {event_id for node in graph.nodes for event_id in node.event_ids}
    graph.supporting_events = [event for event in events if event.event_id in needed]
    return graph
