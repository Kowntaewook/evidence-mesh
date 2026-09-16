"""Generate inert SQLite cases for an actual Electron paging smoke test."""

import argparse
import json
from datetime import UTC, datetime, timedelta

from engine.normalization import normalize_event
from engine.storage import SQLiteRepository
from schemas.results import CaseCreate


def generate(database, sizes):
    repository = SQLiteRepository(database)
    result = []
    for size in sizes:
        case = repository.create_case(CaseCreate(name=f"UI benchmark {size:,}"))
        with repository.connection() as db:

            def rows(count=size, case_id=case.case_id):
                base = datetime(2026, 9, 16, tzinfo=UTC)
                for index in range(count):
                    source = ("memory", "disk", "network")[index % 3]
                    fields = (
                        {"process": {"pid": index + 1, "name": f"fixture-{index:06}.exe"}}
                        if source == "memory"
                        else {"file": {"path": f"C:\\Fixtures\\fixture-{index:06}.txt"}}
                        if source == "disk"
                        else {
                            "network": {
                                "src_ip": "192.0.2.1",
                                "dst_ip": "192.0.2.2",
                                "src_port": index % 65535,
                                "dst_port": 443,
                                "protocol": "TCP",
                            }
                        }
                    )
                    event = normalize_event(
                        {
                            "event_id": f"BENCH-{index:06}",
                            "source": source,
                            "type": "process_observation" if source == "memory" else "observation",
                            "timestamp": base + timedelta(seconds=index),
                            "hostname": "synthetic-benchmark",
                            **fields,
                        }
                    )
                    yield (
                        case_id,
                        event.event_id,
                        event.timestamp.isoformat(),
                        source,
                        event.model_dump_json(),
                        *repository._indexed(event),
                    )

            db.executemany(
                "INSERT INTO events(case_id,event_id,timestamp,source,data,pid,event_type,sha256,"
                "ip,domain,normalized_path,artifact_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                rows(),
            )
            db.execute("UPDATE cases SET revision=1 WHERE case_id=?", (case.case_id,))
        result.append({"case_id": case.case_id, "count": size})
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--sizes", default="10000,50000,100000")
    arguments = parser.parse_args()
    print(json.dumps(generate(arguments.database, [int(value) for value in arguments.sizes.split(",")])))
