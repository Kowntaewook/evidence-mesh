"""Offline PCAP/PCAPNG decoding via an installed tshark; never opens a capture interface."""

import csv
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path

from engine.ingestion.evidence import ArtifactError, DependencyUnavailable, EvidenceReader, number
from schemas.events import Source
from schemas.imports import ArtifactContext, ImportBatch, ParserRun, RunStatus

FIELDS = (
    "frame.number frame.time_epoch frame.len ip.src ip.dst ipv6.src ipv6.dst "
    "tcp.srcport tcp.dstport udp.srcport udp.dstport tcp.stream udp.stream tcp.flags "
    "dns.id dns.flags.response dns.qry.name dns.qry.type dns.a dns.aaaa dns.resp.name "
    "http.request.method http.host http.request.uri http.user_agent http.response.code http.content_type "
    "tls.handshake.extensions_server_name tls.handshake.version tls.record.version"
).split()


def first(row, name):
    return row.get(name, "").split(",")[0] or None


def epoch(value):
    try:
        seconds = Decimal(value)
        if not seconds.is_finite():
            raise ValueError("nonfinite epoch")
        # datetime retains microseconds; original decimal value remains in provenance.
        return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=int(seconds * 1_000_000))
    except (InvalidOperation, ValueError, OverflowError, TypeError) as exc:
        raise ArtifactError(f"Invalid frame timestamp: {value}") from exc


class PcapAdapter:
    def __init__(self, context: ArtifactContext, executable: str | None = None, timeout: int = 180):
        self.context, self.executable, self.timeout = context, executable, timeout

    def load_file(self, path: Path) -> ImportBatch:
        run = ParserRun(parser="TsharkAdapter", source=Source.NETWORK, status=RunStatus.FAILED)
        batch = ImportBatch(runs=[run])
        try:
            reader = EvidenceReader(path, Source.NETWORK, "PCAP", self.context, run.parser)
            run.artifact = reader.artifact
            executable = self.executable or shutil.which("tshark")
            if not executable:
                raise DependencyUnavailable("tshark is not installed; PCAP was not imported")
            run.command = [
                executable,
                "-n",
                "-r",
                str(Path(path).resolve()),
                "-T",
                "fields",
                "-E",
                "header=y",
                "-E",
                "separator=/t",
                "-E",
                "quote=d",
                "-E",
                "occurrence=a",
                "-E",
                "aggregator=,",
            ]
            for field in FIELDS:
                run.command.extend(["-e", field])
            with tempfile.TemporaryFile(mode="w+", encoding="utf-8", newline="") as decoded:
                with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as errors:
                    try:
                        result = subprocess.run(
                            run.command, stdout=decoded, stderr=errors, timeout=self.timeout, check=False
                        )
                    finally:
                        errors.seek(0)
                        run.stderr = errors.read(65536) or None
                    if result.returncode:
                        run.exit_code = result.returncode
                        raise ArtifactError(f"tshark exited with code {result.returncode}: {run.stderr}")
                    run.exit_code = result.returncode
                decoded.seek(0)
                records = csv.DictReader(decoded, delimiter="\t", strict=True)
                if records.fieldnames != FIELDS:
                    raise ArtifactError("tshark output fields do not match the requested schema")
                events, flows = [], {}
                for row in records:
                    if None in row or any(value is None for value in row.values()):
                        raise ArtifactError("Malformed tshark output row")
                    run.row_count += 1
                    events.extend(self._packet(reader, row, flows))
                for flow in flows.values():
                    events.append(self._flow(reader, flow))
                if not run.row_count:
                    raise ArtifactError("Capture contains no packets")
                if not events:
                    run.warnings.append("Capture parsed, but contains no supported TCP/UDP IP traffic")
                batch.events = sorted(events, key=lambda e: (e.timestamp, e.event_id))
            run.status, run.event_count = RunStatus.SUCCESS, len(batch.events)
        except (DependencyUnavailable, FileNotFoundError) as exc:
            # A missing capture is an input failure, a missing executable is unavailable.
            run.status = RunStatus.UNAVAILABLE if run.artifact else RunStatus.FAILED
            run.error = str(exc)
        except Exception as exc:
            run.error = f"{type(exc).__name__}: {exc}"
        run.finished_at = datetime.now(UTC)
        return batch

    def _packet(self, reader, row, flows):
        frame = number(first(row, "frame.number"), "frame.number", True)
        observed = epoch(first(row, "frame.time_epoch"))
        size = number(first(row, "frame.len"), "frame.len", True)
        protocol = "TCP" if first(row, "tcp.srcport") is not None else "UDP"
        prefix = protocol.lower()
        network = {
            "src_ip": first(row, "ip.src") or first(row, "ipv6.src"),
            "dst_ip": first(row, "ip.dst") or first(row, "ipv6.dst"),
            "src_port": number(first(row, prefix + ".srcport"), "src_port", maximum=65535),
            "dst_port": number(first(row, prefix + ".dstport"), "dst_port", maximum=65535),
            "protocol": protocol,
            "stream_id": first(row, prefix + ".stream"),
        }
        if any(network[key] is None for key in ("src_ip", "dst_ip", "src_port", "dst_port")):
            return []
        endpoints = sorted(
            [(network["src_ip"], network["src_port"]), (network["dst_ip"], network["dst_port"])]
        )
        flow_key = (protocol, network["stream_id"], *endpoints)
        flow = flows.setdefault(
            flow_key,
            {
                "network": network.copy(),
                "start": observed,
                "end": observed,
                "frames": [],
                "bytes": 0,
                "flags": set(),
                "first": row,
            },
        )
        flow["start"], flow["end"] = min(flow["start"], observed), max(flow["end"], observed)
        flow["frames"].append(frame)
        flow["bytes"] += size
        flags = first(row, "tcp.flags")
        if flags:
            flow["flags"].add(flags)
        events = []

        def emit(event_type, extra, suffix=""):
            events.append(
                reader.event(
                    f"frame:{frame}",
                    row,
                    frame - 1,
                    event_type,
                    observed,
                    suffix=suffix,
                    timestamp_precision=0.000001,
                    network={**network, **extra},
                    attributes={"frame_number": frame},
                )
            )

        query = first(row, "dns.qry.name")
        if first(row, "dns.id") is not None:
            response = str(first(row, "dns.flags.response")).casefold() in {"1", "true"}
            resolved = [
                value for field in ("dns.a", "dns.aaaa") for value in row.get(field, "").split(",") if value
            ]
            emit(
                "dns_response" if response else "dns_query",
                {
                    "dns_query": query,
                    "dns_query_type": first(row, "dns.qry.type"),
                    "dns_response": response,
                    "dns_id": first(row, "dns.id"),
                    "resolved_ips": resolved,
                },
            )
        if any(first(row, name) is not None for name in ("http.request.method", "http.response.code")):
            emit(
                "http_request" if first(row, "http.request.method") else "http_response",
                {
                    "http": {
                        "method": first(row, "http.request.method"),
                        "host": first(row, "http.host"),
                        "uri": first(row, "http.request.uri"),
                        "user_agent": first(row, "http.user_agent"),
                        "status": number(first(row, "http.response.code"), "HTTP status"),
                        "content_type": first(row, "http.content_type"),
                    }
                },
            )
        sni = first(row, "tls.handshake.extensions_server_name")
        version = first(row, "tls.handshake.version") or first(row, "tls.record.version")
        if sni or version:
            # SNI is carried by ClientHello. Other TLS records use the observed flow orientation.
            client = network if sni else {}
            emit(
                "tls_client_hello" if sni else "tls_record",
                {
                    "tls": {
                        "sni": sni,
                        "version": version,
                        "client_ip": client.get("src_ip"),
                        "server_ip": client.get("dst_ip"),
                        "server_port": client.get("dst_port"),
                    }
                },
            )
        return events

    def _flow(self, reader, flow):
        frames = flow["frames"]
        flags = sorted(flow["flags"])
        state = (
            "RST observed"
            if any(int(flag, 16) & 4 for flag in flags)
            else ("FIN observed" if any(int(flag, 16) & 1 for flag in flags) else "observed packets")
        )
        return reader.event(
            f"flow:{flow['network']['protocol']}:{frames[0]}",
            {"frames": frames, "first_packet": flow["first"]},
            frames[0] - 1,
            "network_flow",
            flow["start"],
            timestamp_semantics="flow_start",
            timestamp_precision=0.000001,
            network={
                **flow["network"],
                "end_time": flow["end"],
                "packet_count": len(frames),
                "byte_count": flow["bytes"],
                "flags": flags,
                "state": state,
            },
            attributes={"frame_numbers": frames, "orientation": "first observed packet"},
        )
