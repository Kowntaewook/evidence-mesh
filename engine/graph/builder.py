import hashlib
from typing import Protocol

from engine.graph.artifacts import attach_provenance, extend_graph
from engine.normalization.windows import path_key
from schemas.events import Event
from schemas.results import Correlation, Edge, EdgeKind, IncidentGraph, Node, NodeKind


class GraphBuilder(Protocol):
    def build(
        self, events: list[Event], correlations: list[Correlation], root: str | None = None
    ) -> IncidentGraph: ...


def stable_id(kind: str, identity: str) -> str:
    return f"{kind}:{hashlib.sha256(identity.encode()).hexdigest()[:24]}"


def event_label(event: Event) -> str:
    if event.network and event.network.dns_query:
        return event.network.dns_query
    if event.network and event.network.dst_ip:
        port = event.network.dst_port if event.network.dst_port is not None else "*"
        return f"{event.network.dst_ip}:{port}"
    if event.file:
        return event.file.path or event.file.name or event.type
    if event.process:
        return f"{event.process.name or 'Process'} (PID {event.process.pid})"
    return event.type


def build_graph(
    events: list[Event], correlations: list[Correlation], root: str | None = None
) -> IncidentGraph:
    nodes: dict[str, Node] = {}
    edges: list[Edge] = []
    process_nodes: dict[str, str] = {}
    parent_links: list[tuple[Event, str]] = []

    def entity(event: Event, kind: NodeKind, identity: str, label: str) -> str:
        node_id = stable_id(kind.value, identity)
        if node_id not in nodes:
            nodes[node_id] = Node(id=node_id, kind=kind, label=label, event_ids=[])
        if event.event_id not in nodes[node_id].event_ids:
            nodes[node_id].event_ids.append(event.event_id)
        edge_id = stable_id("observation", event.event_id + node_id)
        edges.append(
            Edge(
                id=edge_id,
                source=f"event:{event.event_id}",
                target=node_id,
                kind=EdgeKind.OBSERVED,
                event_ids=[event.event_id],
            )
        )
        return node_id

    for event in events:
        node_id = f"event:{event.event_id}"
        nodes[node_id] = Node(
            id=node_id, kind=NodeKind.EVENT, label=event_label(event), event_ids=[event.event_id]
        )
        scope = event.hostname or f"unknown:{event.event_id}"
        process_id = None
        if event.process:
            process = event.process
            lifetime = process.creation_time.isoformat() if process.creation_time else event.event_id
            process_id = entity(
                event,
                NodeKind.PROCESS,
                process.instance_id or f"{scope}:{process.pid}:{lifetime}",
                f"{process.name or 'Process'} (PID {process.pid})",
            )
            if process.instance_id:
                process_nodes[process.instance_id] = process_id
            if process.parent_instance_id:
                parent_links.append((event, process_id))
        if event.file:
            file = event.file
            identity = f"{scope}:{path_key(file.path)}:{file.sha256 or ''}" if file.path else event.event_id
            file_id = entity(event, NodeKind.FILE, identity, file.path or file.name or "Unknown file")
            if process_id and event.type == "module_load":
                edges.append(
                    Edge(
                        id=stable_id("loaded", event.event_id),
                        source=process_id,
                        target=file_id,
                        kind=EdgeKind.LOADED,
                        event_ids=[event.event_id],
                    )
                )
        if event.network:
            network = event.network
            domain_id = None
            if network.dns_query:
                domain_id = entity(event, NodeKind.DOMAIN, network.dns_query, network.dns_query)
            for ip in sorted(set(filter(None, [network.dst_ip, *network.resolved_ips]))):
                ip_id = entity(event, NodeKind.IP, ip, ip)
                if domain_id and ip in network.resolved_ips:
                    edges.append(
                        Edge(
                            id=stable_id("resolution", event.event_id + ip),
                            source=domain_id,
                            target=ip_id,
                            kind=EdgeKind.RESOLVED,
                            event_ids=[event.event_id],
                        )
                    )
                if (
                    process_id
                    and network.dst_ip == ip
                    and event.type in {"network_connection", "socket"}
                    and (network.state or "").upper() != "LISTENING"
                    and ip not in {"0.0.0.0", "::"}
                ):
                    edges.append(
                        Edge(
                            id=stable_id("socket", event.event_id + ip),
                            source=process_id,
                            target=ip_id,
                            kind=EdgeKind.CONNECTED_TO,
                            event_ids=[event.event_id],
                        )
                    )
        if event.user:
            user = event.user
            entity(
                event,
                NodeKind.USER,
                f"{scope}:{user.sid or user.name or event.event_id}",
                user.name or user.sid or "Unknown user",
            )
        registry = event.attributes.get("registry_key")
        if isinstance(registry, str):
            entity(event, NodeKind.REGISTRY, f"{scope}:{registry.casefold()}", registry)

    parents: dict[tuple[str, str], list[str]] = {}
    for event, child_id in parent_links:
        assert event.process is not None
        parent_id = process_nodes.get(event.process.parent_instance_id or "")
        if parent_id and parent_id != child_id:
            parents.setdefault((parent_id, child_id), []).append(event.event_id)
    for (parent_id, child_id), event_ids in parents.items():
        edges.append(
            Edge(
                id=stable_id("parent", parent_id + child_id),
                source=parent_id,
                target=child_id,
                kind=EdgeKind.PARENT_OF,
                event_ids=sorted(set(event_ids)),
            )
        )

    extend_graph(events, correlations, nodes, edges, entity, stable_id)
    for correlation in correlations:
        if (
            f"event:{correlation.source_event}" not in nodes
            or f"event:{correlation.target_event}" not in nodes
        ):
            raise ValueError("Correlation refers to an event outside graph input")
        edges.append(
            Edge(
                id=stable_id("correlation", correlation.source_event + ":" + correlation.target_event),
                source=f"event:{correlation.source_event}",
                target=f"event:{correlation.target_event}",
                kind=EdgeKind.CORRELATED_WITH,
                event_ids=[correlation.source_event, correlation.target_event],
                score=correlation.score,
                reasons=correlation.reasons,
            )
        )
    # Multiple typed relationships can reference the same entity observation.
    edges = list({edge.id: edge for edge in edges}.values())
    grouped = {}
    for edge in edges:
        key = (
            edge.id
            if edge.kind in {EdgeKind.OBSERVED, EdgeKind.CORRELATED_WITH}
            else (edge.source, edge.target, edge.kind)
        )
        if key not in grouped:
            grouped[key] = edge
        else:
            previous = grouped[key]
            previous.event_ids = sorted(set(previous.event_ids) | set(edge.event_ids))
            previous.support_count += edge.support_count
            if (edge.score or 0) > (previous.score or 0):
                previous.score, previous.reasons = edge.score, edge.reasons
    edges = list(grouped.values())
    attach_provenance(events, edges)
    return IncidentGraph(
        nodes=sorted(nodes.values(), key=lambda node: node.id),
        edges=sorted(edges, key=lambda edge: edge.id),
        root_event_id=root,
    )
