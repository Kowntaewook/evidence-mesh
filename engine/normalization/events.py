from copy import deepcopy
from ipaddress import ip_address
from typing import Any

from schemas.events import Event


def normalize_event(record: dict[str, Any] | Event) -> Event:
    """Copy, validate and normalize without modifying input evidence."""
    data = record.model_dump(mode="json") if isinstance(record, Event) else deepcopy(record)
    event = Event.model_validate(data)
    # Work on plain data to validate once after all canonical transformations.
    data = event.model_dump(mode="json")
    if event.hostname:
        data["hostname"] = event.hostname.strip().casefold()
    if event.process and not event.process.command_line:
        command = event.attributes.get("command_line")
        if isinstance(command, str):
            data["process"]["command_line"] = command
    if event.network:
        network = data["network"]
        for field in ("src_ip", "dst_ip"):
            if network[field]:
                network[field] = str(ip_address(network[field]))
        network["resolved_ips"] = sorted({str(ip_address(ip)) for ip in network["resolved_ips"]})
        if network["protocol"]:
            network["protocol"] = network["protocol"].upper()
        if network["dns_query"]:
            network["dns_query"] = network["dns_query"].rstrip(".").casefold()
    return Event.model_validate(data)


def normalize_events(records: list[dict[str, Any] | Event]) -> list[Event]:
    if not records:
        raise ValueError("No events supplied; evidence was not imported")
    events = [normalize_event(record) for record in records]
    if len({event.event_id for event in events}) != len(events):
        raise ValueError("Duplicate event_id in input batch")
    return events
