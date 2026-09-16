from engine.correlation.base import reason, same_host
from schemas.events import Event
from schemas.results import Reason


class NetworkRule:
    def evaluate(self, left: Event, right: Event) -> list[Reason]:
        if "extraction_time" in {left.timestamp_semantics, right.timestamp_semantics}:
            return []
        a, b = left.network, right.network
        if not a or not b:
            return []
        results = []
        seconds = max(
            0,
            (left.timestamp - (b.end_time or right.timestamp)).total_seconds(),
            (right.timestamp - (a.end_time or left.timestamp)).total_seconds(),
        )
        # Sockets and DNS answers are time-bounded; a reused server is not identity.
        if seconds > 60:
            return []
        tuple_fields = ("src_ip", "src_port", "dst_ip", "dst_port", "protocol")
        exact = all(getattr(a, f) is not None and getattr(a, f) == getattr(b, f) for f in tuple_fields)
        reverse = (
            a.protocol
            and a.protocol == b.protocol
            and all(
                getattr(a, field) is not None and getattr(a, field) == getattr(b, other)
                for field, other in (
                    ("src_ip", "dst_ip"),
                    ("src_port", "dst_port"),
                    ("dst_ip", "src_ip"),
                    ("dst_port", "src_port"),
                )
            )
        )
        if exact or reverse:
            results.append(
                reason(
                    "same_socket_tuple",
                    60,
                    f"{a.src_ip}:{a.src_port} → {a.dst_ip}:{a.dst_port} {a.protocol}",
                    "network",
                )
            )
            if (a.end_time or b.end_time) and seconds == 0:
                results.append(
                    reason(
                        "flow_temporal_overlap",
                        10,
                        "Recorded connection intervals overlap",
                        "timestamp",
                        "network.end_time",
                    )
                )
        elif a.dst_ip and a.dst_ip == b.dst_ip:
            conflicts = any(
                getattr(a, f) is not None and getattr(b, f) is not None and getattr(a, f) != getattr(b, f)
                for f in ("dst_port", "protocol", "src_ip", "src_port")
            )
            if (
                not conflicts
                and a.dst_port is not None
                and a.dst_port == b.dst_port
                and same_host(left, right)
            ):
                results.append(
                    reason(
                        "same_destination_endpoint",
                        40,
                        f"{a.dst_ip}:{a.dst_port}",
                        "network.dst_ip",
                        "network.dst_port",
                    )
                )
        for dns_event, connection in ((left, right), (right, left)):
            dns, net = dns_event.network, connection.network
            assert dns is not None and net is not None
            client_ip = dns.dst_ip if dns.dns_response else dns.src_ip
            same_client = (
                bool(client_ip == net.src_ip)
                if client_ip and net.src_ip
                else same_host(dns_event, connection)
            )
            delta = (connection.timestamp - dns_event.timestamp).total_seconds()
            if dns.dns_query and net.dst_ip in dns.resolved_ips and same_client and 0 <= delta <= 60:
                results.extend(
                    [
                        reason(
                            "dns_resolved_destination",
                            40,
                            f"{dns.dns_query} resolved to {net.dst_ip}",
                            "network.resolved_ips",
                            "network.dst_ip",
                        ),
                        reason(
                            "dns_preceded_connection",
                            10,
                            f"DNS preceded connection by {delta:g} seconds",
                            "timestamp",
                        ),
                    ]
                )
        a_client = a.dst_ip if a.dns_response else a.src_ip
        b_client = b.dst_ip if b.dns_response else b.src_ip
        same_dns_client = bool(a_client == b_client) if a_client and b_client else same_host(left, right)
        if (
            a.dns_query
            and a.dns_query == b.dns_query
            and same_dns_client
            and (same_host(left, right) or a.dns_id == b.dns_id)
        ):
            results.append(reason("same_dns_query", 35, a.dns_query, "network.dns_query"))
        return results
