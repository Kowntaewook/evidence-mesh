"""Deterministic semantic postings plus time buckets; no default all-event pair scan."""

from collections import defaultdict
from math import floor

from engine.normalization.windows import basename, command_tokens, path_key


def domains(event):
    network = event.network
    if not network:
        return set()
    return {
        value.rstrip(".").casefold()
        for value in (
            network.dns_query,
            network.tls.sni if network.tls else None,
            network.http.host if network.http else None,
        )
        if value
    }


def identities(event):
    """Return index entries and lookup entries. Weak names alone never initiate a search."""
    entries, queries = set(), set()
    process, file, network = event.process, event.file, event.network
    if process:
        entries.add(("pid", (event.hostname, process.pid)))
        if process.ppid is not None:
            queries.add(("pid", (event.hostname, process.ppid)))
            queries.add(("parent_pid", (event.hostname, process.ppid)))
        if process.creation_time:
            entries.add(("parent_pid", (event.hostname, process.pid)))
        if process.instance_id:
            entries.add(("instance", process.instance_id))
        if process.parent_instance_id:
            queries.add(("instance", process.parent_instance_id))
        if process.creation_time:
            entries.add(("lifetime", (event.hostname, process.pid, process.creation_time)))
        if process.name:
            entries.add(("process_name", process.name.casefold()))
        if process.path:
            entries.add(("executable", path_key(process.path)))
            queries.add(("registry_path", path_key(process.path)))
        for token in command_tokens(process.command_line):
            queries.add(("path" if "\\" in token or "/" in token else "filename", token))
    if file:
        if file.path:
            entries.add(("path", path_key(file.path)))
            if event.registry:
                entries.add(("registry_path", path_key(file.path)))
                queries.add(("executable", path_key(file.path)))
        if file.path or file.name:
            entries.add(("filename", basename(file.path or file.name)))
        queries.update(("path", path_key(value)) for value in file.references)
        if file.sha256:
            entries.add(("hash", file.sha256))
        if file.volume_id and file.record_number is not None and file.sequence_number is not None:
            entries.add(("mft", (event.hostname, file.volume_id, file.record_number, file.sequence_number)))
        if file.file_object:
            acquisition = event.metadata.get("acquisition_id")
            if acquisition:
                entries.add(("file_object", (acquisition, file.file_object)))
    if event.hash and event.hash.sha256:
        entries.add(("hash", event.hash.sha256))
    if event.prefetch:
        queries.add(("process_name", basename(event.prefetch.executable)))
        if event.prefetch.executable_path:
            queries.add(("executable", path_key(event.prefetch.executable_path)))
    if network:
        for ip in filter(None, [network.src_ip, network.dst_ip, *network.resolved_ips]):
            entries.add(("ip", ip))
        for port in filter(lambda value: value is not None, [network.src_port, network.dst_port]):
            entries.add(("port", port))
        endpoints = ((network.src_ip, network.src_port), (network.dst_ip, network.dst_port))
        complete = all(value is not None for endpoint in endpoints for value in endpoint) and network.protocol
        if complete:
            entries.add(("tuple", (network.protocol, *sorted(endpoints))))
        if network.dst_ip and network.dst_port is not None:
            endpoint = (event.hostname, network.dst_ip, network.dst_port)
            entries.add(("endpoint" if complete else "partial_endpoint", endpoint))
            queries.add(("partial_endpoint", endpoint))
            if not complete:
                queries.add(("endpoint", endpoint))
        client = network.dst_ip if network.dns_response else network.src_ip
        for ip in network.resolved_ips:
            queries.add(("destination", (client, ip)))
            if event.hostname:
                queries.add(
                    ("destination_host" if client is None else "destination_missing", (event.hostname, ip))
                )
        if network.dst_ip:
            entries.add(("destination", (network.src_ip, network.dst_ip)))
            if event.hostname:
                entries.add(("destination_host", (event.hostname, network.dst_ip)))
                if network.src_ip is None:
                    entries.add(("destination_missing", (event.hostname, network.dst_ip)))
        for name in domains(event):
            entries.add(("domain", (client, name)))
            if network.dns_query and event.hostname:
                entries.add(("domain_host", (event.hostname, name)))
                if client is None:
                    entries.add(("domain_missing", (event.hostname, name)))
                queries.add(("domain_host" if client is None else "domain_missing", (event.hostname, name)))
    queries.update(
        entry
        for entry in entries
        if entry[0]
        not in {
            "filename",
            "process_name",
            "ip",
            "port",
            "destination",
            "parent_pid",
            "executable",
            "registry_path",
            "endpoint",
            "partial_endpoint",
            "destination_host",
            "destination_missing",
            "domain_host",
            "domain_missing",
        }
    )
    return entries, queries


class EventIndex:
    def __init__(self, events):
        self.events, self.queries = events, []
        self.postings = defaultdict(list)
        self.buckets = defaultdict(list)
        self.unknown = defaultdict(list)
        for index, event in enumerate(events):
            entries, queries = identities(event)
            self.queries.append(queries)
            bucket = floor(event.timestamp.timestamp() / 60)
            for key in entries:
                self.postings[key].append(index)
                self.buckets[key, bucket].append(index)
                if event.timestamp_semantics == "extraction_time":
                    self.unknown[key].append(index)

    def pairs(self):
        # Query both directions: command references and parent links are asymmetric lookups.
        pairs = set()
        for index, event in enumerate(self.events):
            bucket = floor(event.timestamp.timestamp() / 60)
            for key in self.queries[index]:
                if key[0] in {
                    "hash",
                    "instance",
                    "lifetime",
                    "mft",
                    "file_object",
                    "parent_pid",
                    "tuple",
                } or (
                    event.timestamp_semantics == "extraction_time"
                    and key[0] in {"path", "filename", "pid", "executable", "registry_path"}
                ):
                    matches = self.postings.get(key, [])
                    for other in matches:
                        if other != index:
                            pairs.add(tuple(sorted((index, other))))
                else:
                    for nearby in (bucket - 1, bucket, bucket + 1):
                        for other in self.buckets.get((key, nearby), []):
                            if other != index:
                                pairs.add(tuple(sorted((index, other))))
                    if key[0] in {"path", "filename", "pid", "executable", "registry_path"}:
                        for other in self.unknown.get(key, []):
                            if other != index:
                                pairs.add(tuple(sorted((index, other))))
        return sorted(pairs)

    def sizes(self):
        result = defaultdict(int)
        for (kind, _), indices in self.postings.items():
            result[kind] += len(indices)
        result["timestamp_bucket"] = len(self.buckets)
        return dict(sorted(result.items()))
