"""Offline PCAP/PCAPNG decoding via an installed tshark; never opens a capture interface."""

import csv
import hashlib
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path

from engine.ingestion.evidence import ArtifactError, DependencyUnavailable, EvidenceReader, number
from engine.runtime import resolve_tshark, workspace_root
from schemas.events import Source
from schemas.imports import ArtifactContext, ImportBatch, ParserRun, RunStatus

FIELDS = (
    "frame.number frame.time_epoch frame.len ip.src ip.dst ipv6.src ipv6.dst "
    "tcp.srcport tcp.dstport udp.srcport udp.dstport tcp.stream udp.stream tcp.flags "
    "dns.id dns.flags.response dns.qry.name dns.qry.type dns.a dns.aaaa dns.resp.name "
    "http.request.method http.host http.request.uri http.user_agent http.response.code http.content_type "
    "tls.handshake.extensions_server_name tls.handshake.version tls.record.version "
    "http.file_data http.body.reassembled.data http.content_length http.transfer_encoding "
    "http.content_encoding tls.app_data_proto"
).split()
MAX_BODY_BYTES = 32 * 1024 * 1024
BODY_FIELDS = {"http.file_data", "http.body.reassembled.data"}


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
    def __init__(
        self,
        context: ArtifactContext,
        executable: str | None = None,
        timeout: int = 180,
        workspace: Path | None = None,
    ):
        self.context, self.executable, self.timeout = context, executable, timeout
        self.workspace = Path(workspace) if workspace else workspace_root()

    def load_file(self, path: Path) -> ImportBatch:
        run = ParserRun(parser="TsharkAdapter", source=Source.NETWORK, status=RunStatus.FAILED)
        batch = ImportBatch(runs=[run])
        try:
            reader = EvidenceReader(path, Source.NETWORK, "PCAP", self.context, run.parser)
            run.artifact = reader.artifact
            executable = resolve_tshark(self.executable, system=shutil.which)
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
            for option in (
                "tcp.desegment_tcp_streams:TRUE",
                "http.desegment_body:TRUE",
                "http.dechunk_body:TRUE",
                "http.decompress_body:FALSE",
            ):
                run.command.extend(["-o", option])
            if self.context.tls_keylog_file:
                keylog = Path(self.context.tls_keylog_file).expanduser().resolve()
                if not keylog.is_file() or keylog.stat().st_size > 64 * 1024 * 1024:
                    raise ArtifactError("Supplied TLS key log must be an existing file up to 64 MiB")
                run.command.extend(["-o", f"tls.keylog_file:{keylog}"])
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
                csv.field_size_limit(MAX_BODY_BYTES * 2 + 1024)
                records = csv.DictReader(decoded, delimiter="\t", strict=True)
                if records.fieldnames != FIELDS:
                    raise ArtifactError("tshark output fields do not match the requested schema")
                events, flows = [], {}
                for row in records:
                    if None in row or any(value is None for value in row.values()):
                        raise ArtifactError("Malformed tshark output row")
                    run.row_count += 1
                    events.extend(self._packet(reader, row, flows, run.warnings))
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

    def _packet(self, reader, row, flows, warnings=None):
        warnings = [] if warnings is None else warnings
        body = {}
        try:
            body = self._recover_body(reader, row)
        except (ArtifactError, OSError, ValueError) as exc:
            warnings.append(f"Frame {first(row, 'frame.number')}: HTTP body not recovered: {exc}")
        # Keep packet fields and a derived-file reference, without duplicating
        # potentially large body bytes in every event/flow provenance record.
        row = {key: value for key, value in row.items() if key not in BODY_FIELDS}
        if body:
            row["recovered_body_sha256"] = body["body_sha256"]
            row["recovered_body_path"] = body["recovered_path"]
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

        def emit(event_type, extra, suffix="", **fields):
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
                    **fields,
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
            decrypted = bool(self.context.tls_keylog_file and first(row, "tls.app_data_proto"))
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
                        "transfer_encoding": first(row, "http.transfer_encoding"),
                        "content_encoding": first(row, "http.content_encoding"),
                        "decrypted_with_supplied_key": decrypted,
                        **body,
                    }
                },
                **(
                    {
                        "file": {
                            "path": body["recovered_path"],
                            "sha256": body["body_sha256"],
                            "size": body["body_size"],
                        }
                    }
                    if body
                    else {}
                ),
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
                        "key_log_supplied": bool(self.context.tls_keylog_file),
                        "decryption": "decrypted_with_supplied_key"
                        if self.context.tls_keylog_file
                        and first(row, "tls.app_data_proto")
                        and events
                        and events[-1].network.http
                        else "metadata_only",
                    }
                },
            )
        return events

    def _recover_body(self, reader, row):
        encoded = row.get("http.file_data") or row.get("http.body.reassembled.data")
        if not encoded:
            return {}
        if "," in encoded:
            raise ArtifactError("Multiple HTTP bodies share one packet; body association is ambiguous")
        if len(encoded) > MAX_BODY_BYTES * 2:
            raise ArtifactError("Body exceeds the 32 MiB recovery bound")
        content = bytes.fromhex(encoded.replace(":", ""))
        declared = first(row, "http.content_length")
        if declared and not first(row, "http.transfer_encoding") and int(declared) != len(content):
            raise ArtifactError("Incomplete Content-Length body")
        digest = hashlib.sha256(content).hexdigest()
        target = (
            self.workspace / "derived" / "network" / reader.artifact.sha256 / "bodies" / (digest + ".bin")
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with target.open("xb") as output:
                output.write(content)
        except FileExistsError:
            if (
                target.stat().st_size != len(content)
                or hashlib.sha256(target.read_bytes()).hexdigest() != digest
            ):
                raise ArtifactError("Existing derived body failed integrity verification") from None
        return {"body_sha256": digest, "body_size": len(content), "recovered_path": str(target.resolve())}

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
