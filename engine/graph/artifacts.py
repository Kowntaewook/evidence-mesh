"""Typed graph relationships supported by normalized observations and scored links."""

from engine.correlation.base import reason
from engine.correlation.index import domains
from engine.normalization.windows import command_tokens, path_key
from schemas.results import Edge, EdgeKind, NodeKind


def extend_graph(events, correlations, nodes, edges, entity, stable_id):
    observed = {}
    for node in nodes.values():
        for event_id in node.event_ids:
            observed[event_id, node.kind] = node.id

    def link(event, source, target, kind, details, correlation=None):
        if not source or not target or source == target:
            return
        event_ids = (
            [event.event_id] if correlation is None else [correlation.source_event, correlation.target_event]
        )
        edges.append(
            Edge(
                id=stable_id("typed", ":".join([*event_ids, source, target, kind])),
                source=source,
                target=target,
                kind=kind,
                event_ids=event_ids,
                score=correlation.score if correlation else 100,
                reasons=correlation.reasons
                if correlation
                else [reason("recorded_relationship", 100, details, "provenance", "raw_reference")],
            )
        )

    for event in events:
        process = observed.get((event.event_id, NodeKind.PROCESS))
        file = observed.get((event.event_id, NodeKind.FILE))
        scope = event.hostname or event.metadata.get("acquisition_id") or event.event_id
        observation = "event:" + event.event_id
        if event.file:
            item = event.file
            if item.record_number is not None:
                record = entity(
                    event,
                    NodeKind.MFT_RECORD,
                    f"{scope}:{item.volume_id}:{item.record_number}:{item.sequence_number}",
                    f"MFT {item.record_number}:"
                    f"{item.sequence_number if item.sequence_number is not None else '?'}",
                )
                link(event, record, file, EdgeKind.REFERENCES, "File reference recorded in NTFS artifact")
            if item.file_object:
                obj = entity(
                    event,
                    NodeKind.FILE_OBJECT,
                    f"{event.metadata.get('acquisition_id', event.event_id)}:{item.file_object}",
                    f"FILE_OBJECT {item.file_object}",
                )
                link(event, process, obj, EdgeKind.REFERENCES, "Memory row records this file object")
                link(event, obj, file, EdgeKind.REFERENCES, "FILE_OBJECT references the recorded file name")
                if event.artifact_type == "dumpfiles":
                    link(
                        event,
                        file,
                        obj,
                        EdgeKind.EXTRACTED_FROM,
                        "Recovered bytes and SHA-256 reference FILE_OBJECT",
                    )
            if event.handle:
                link(
                    event, process, file, EdgeKind.OPENED, "File handle observed in the process handle table"
                )
            action = {
                "file_created": EdgeKind.CREATED,
                "file_modified": EdgeKind.MODIFIED,
                "file_deleted": EdgeKind.DELETED,
            }.get(event.type)
            if action:
                link(
                    event,
                    process or observation,
                    file,
                    action,
                    "Artifact records file activity at its timestamp",
                )
            for path in item.references:
                referenced = entity(event, NodeKind.FILE, f"{scope}:{path_key(path)}:", path)
                link(
                    event,
                    file or observation,
                    referenced,
                    EdgeKind.REFERENCES,
                    "Referenced file in Prefetch; this does not prove that file executed",
                )
        if event.module:
            module = event.module
            kind = NodeKind.DLL if event.process else NodeKind.MODULE
            node = entity(
                event,
                kind,
                f"{scope}:{module.path or event.file.path if event.file else module.name}:"
                f"{module.base_address_hex or module.base_address}",
                module.name or (event.file.path if event.file else None) or "Module",
            )
            link(event, node, file, EdgeKind.REFERENCES, "Module observation records this image path")
        if event.memory_region:
            region = event.memory_region
            node = entity(
                event,
                NodeKind.MEMORY_REGION,
                f"{process or observation}:{region.start}",
                f"{region.start}–{region.end or '?'} {region.protection or ''}",
            )
            link(
                event,
                process,
                node,
                EdgeKind.ASSOCIATED_WITH,
                "Region belongs to the recorded process address space",
            )
        if event.service:
            service = event.service
            node = entity(event, NodeKind.SERVICE, f"{scope}:{service.name.casefold()}", service.name)
            link(event, node, process, EdgeKind.ASSOCIATED_WITH, "Service row records this process PID")
            # Preserve service command text. Only an unambiguous executable token becomes a file entity.
            binaries = [token for token in command_tokens(service.binary_path) if token.endswith(".exe")]
            if len(binaries) == 1:
                binary = entity(event, NodeKind.FILE, f"{scope}:{binaries[0]}:", binaries[0])
                link(
                    event, node, binary, EdgeKind.USES_BINARY, "Service configuration records this executable"
                )
            if service.service_dll:
                binary = entity(
                    event, NodeKind.DLL, f"{scope}:{path_key(service.service_dll)}", service.service_dll
                )
                link(event, node, binary, EdgeKind.USES_BINARY, "Service configuration records a service DLL")
        if event.registry:
            registry = event.registry
            node = entity(
                event,
                NodeKind.REGISTRY_ARTIFACT,
                f"{scope}:{registry.artifact}:{registry.hive}:{registry.path}:{event.event_id}",
                registry.path or registry.artifact,
            )
            link(event, node, file, EdgeKind.REFERENCES, "Registry-derived artifact records this file path")
        if event.driver:
            driver = event.driver
            node = entity(
                event,
                NodeKind.DRIVER,
                f"{scope}:{driver.object_address or driver.start}:{driver.name}",
                driver.name or driver.path or "Driver",
            )
            link(event, node, file, EdgeKind.REFERENCES, "Driver observation records this image path")
        if event.callback:
            callback = event.callback
            module = entity(
                event, NodeKind.MODULE, f"{scope}:{callback.module}", callback.module or "Unknown module"
            )
            link(
                event,
                observation,
                module,
                EdgeKind.REFERENCES,
                f"{callback.type} callback at {callback.address}; module association from parser",
            )
        if event.network:
            network = event.network
            if network.dns_query:
                domain = observed.get((event.event_id, NodeKind.DOMAIN))
                for ip in network.resolved_ips:
                    address = entity(event, NodeKind.IP, ip, ip)
                    link(event, domain, address, EdgeKind.RESOLVED_TO, "DNS response contains this address")
            for name in domains(event) - {network.dns_query}:
                domain = entity(event, NodeKind.DOMAIN, name, name)
                if network.tls and network.tls.server_ip:
                    address = entity(event, NodeKind.IP, network.tls.server_ip, network.tls.server_ip)
                    link(
                        event,
                        domain,
                        address,
                        EdgeKind.ASSOCIATED_WITH,
                        "TLS ClientHello supplied this SNI to this server; not a DNS resolution",
                    )
            if event.type in {"network_flow", "socket", "network_connection"}:
                kind = NodeKind.FLOW if event.type == "network_flow" else NodeKind.SOCKET
                flow = entity(
                    event,
                    kind,
                    event.event_id,
                    f"{network.src_ip}:{network.src_port} → {network.dst_ip}:{network.dst_port}",
                )
                link(
                    event,
                    process,
                    flow,
                    EdgeKind.ASSOCIATED_WITH,
                    "Socket owner observed in memory or process log",
                )
                address = observed.get((event.event_id, NodeKind.IP))
                link(event, flow, address, EdgeKind.REFERENCES, "Recorded remote endpoint")

    by_id = {event.event_id: event for event in events}
    for correlation in correlations:
        for left, right in (
            (correlation.source_event, correlation.target_event),
            (correlation.target_event, correlation.source_event),
        ):
            process, file = observed.get((left, NodeKind.PROCESS)), observed.get((right, NodeKind.FILE))
            rules = {item.rule for item in correlation.reasons}
            if process and file and "command_line_file_path" in rules:
                command = command_tokens(by_id[left].process.command_line)
                kind = EdgeKind.EXECUTED if "-file" in command else EdgeKind.REFERENCES
                link(by_id[left], process, file, kind, "Recorded command line", correlation)
            parent, child = observed.get((left, NodeKind.PROCESS)), observed.get((right, NodeKind.PROCESS))
            if parent and child and "parent_process" in rules:
                if by_id[right].process.ppid == by_id[left].process.pid:
                    link(by_id[left], parent, child, EdgeKind.PARENT_OF, "Recorded PPID", correlation)


def attach_provenance(events, edges):
    by_id = {event.event_id: event for event in events}
    for edge in edges:
        source = [by_id[event_id] for event_id in edge.event_ids]
        edge.timestamp = min(event.timestamp for event in source)
        unique = {
            (p.source_artifact.artifact_id, p.raw_reference.locator, p.plugin): p
            for event in source
            for p in event.provenance
        }
        edge.provenance = list(unique.values())
        if not edge.reasons:
            edge.score = 100
            edge.reasons = [
                reason(
                    "recorded_relationship",
                    100,
                    f"{edge.kind} from normalized source observation",
                    "event_ids",
                    "provenance",
                )
            ]
