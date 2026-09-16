"""Reproducible isolated-process benchmark with semantic groups and genuine noise."""

import argparse
import hashlib
import json
import resource
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from engine.correlation import CorrelationEngine
from engine.storage import SQLiteRepository
from schemas.events import Event
from schemas.results import CaseCreate


def dataset(count):
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for index in range(count):
        group, slot = divmod(index, 10)
        when = base + timedelta(seconds=group * 120)
        path, executable = f"C:\\Evidence\\{group}\\a.ps1", f"C:\\Tools\\{group}\\powershell.exe"
        process = {
            "pid": 4120,
            "creation_time": when,
            "instance_id": f"image-{group}:4120",
            "name": "powershell.exe",
            "path": executable,
            "command_line": f'powershell.exe -File "{path}"',
        }
        client = f"10.{group // 65536}.{group // 256 % 256}.{group % 256}"
        network = {
            "src_ip": client,
            "src_port": 51231,
            "dst_ip": "203.0.113.20",
            "dst_port": 443,
            "protocol": "TCP",
        }
        file = {
            "path": path,
            "sha256": hashlib.sha256(path.encode()).hexdigest(),
            "record_number": group + 100,
            "sequence_number": 1,
            "volume_id": f"volume-{group}",
        }
        fields = [
            {"source": "memory", "type": "process_start", "process": process},
            {"source": "memory", "type": "socket", "process": process, "network": network},
            {
                "source": "memory",
                "type": "handle_observation",
                "process": process,
                "file": file,
                "handle": {"type": "File", "name": path},
            },
            {"source": "disk", "type": "file_observed", "file": file},
            {
                "source": "disk",
                "type": "file_created",
                "file": file,
                "journal": {"usn": group + 1, "reasons": ["FILE_CREATE"]},
            },
            {
                "source": "disk",
                "type": "prefetch_execution",
                "file": {"references": [path]},
                "prefetch": {"executable": "powershell.exe", "executable_path": executable},
            },
            {
                "source": "network",
                "type": "dns_query",
                "hostname": None,
                "network": {
                    "src_ip": client,
                    "dns_query": f"g{group}.example.test",
                    "resolved_ips": ["203.0.113.20"],
                },
            },
            {
                "source": "network",
                "type": "network_flow",
                "hostname": None,
                "network": {
                    **network,
                    "end_time": when + timedelta(seconds=10),
                    "packet_count": 3,
                    "byte_count": 180,
                },
            },
            {
                "source": "network",
                "type": "tls_client_hello",
                "hostname": None,
                "network": {
                    **network,
                    "tls": {
                        "sni": f"g{group}.example.test",
                        "client_ip": client,
                        "server_ip": "203.0.113.20",
                        "server_port": 443,
                    },
                },
            },
            {"source": "disk", "type": "file_observed", "file": {"path": f"D:\\Unrelated\\{group}\\a.ps1"}},
        ][slot]
        yield Event.model_validate(
            {
                "event_id": f"PERF-{index:09}",
                "timestamp": when + timedelta(seconds=slot / 10),
                "hostname": f"host-{group}",
                "artifact_type": "benchmark",
                **fields,
            }
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    database = args.output / f"{args.count}.sqlite3"
    if database.exists():
        raise FileExistsError(database)
    began = time.perf_counter()
    events = list(dataset(args.count))
    generation = time.perf_counter() - began
    repository = SQLiteRepository(database)
    case = repository.create_case(CaseCreate(name=f"Benchmark {args.count}"))
    began = time.perf_counter()
    repository.add_events(case.case_id, events)
    import_seconds = time.perf_counter() - began
    engine = CorrelationEngine()
    began = time.perf_counter()
    correlations = engine.correlate(events)
    correlation_seconds = time.perf_counter() - began
    began = time.perf_counter()
    repository.save_correlations(case.case_id, correlations, 1)
    persist_seconds = time.perf_counter() - began
    with repository.connection() as db:
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    result = {
        "events": args.count,
        "generation_seconds": generation,
        "import_seconds": import_seconds,
        "correlation_seconds": correlation_seconds,
        "persist_correlations_seconds": persist_seconds,
        "peak_memory_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
        "sqlite_bytes": database.stat().st_size,
        "correlations": len(correlations),
        "candidates": engine.stats,
        "python": __import__("sys").version,
        "notes": "Synthetic normalized events; parser decoding and entity graph rendering excluded.",
    }
    (args.output / f"{args.count}.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
