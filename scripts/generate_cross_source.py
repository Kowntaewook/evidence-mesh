"""Reproducible cross-source case: real parsers over synthetic, inert artifact bytes/exports."""

import hashlib
import json
import shutil
from pathlib import Path

from generate_capture import dns, packet, sample_packets, write_capture

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
TARGET = ROOT / "samples" / "cross_source"


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def generate():
    memory = TARGET / "memory" / "volatility"
    memory.mkdir(parents=True, exist_ok=True)
    for directory in ("volatility", "memory_extended"):
        for file in (FIXTURES / directory).glob("*.json"):
            shutil.copyfile(file, memory / file.name)
    # Deliberately not exactly representable as a JavaScript number; typed addresses must remain hex strings.
    for plugin, field in (("handles", "Offset"), ("filescan", "Offset"), ("dumpfiles", "FileObject")):
        rows = json.loads((memory / f"{plugin}.json").read_text())
        rows[0][field] = 0xFFFF800000000123
        save(memory / f"{plugin}.json", rows)
    net = json.loads((memory / "netscan.json").read_text())
    net[0].update(
        LocalAddr="10.0.0.5", LocalPort=51231, ForeignAddr="203.0.113.20", Created="2026-09-16T09:31:26.301Z"
    )
    save(memory / "netscan.json", net)
    recovered = TARGET / "memory" / "recovered"
    recovered.mkdir(parents=True, exist_ok=True)
    data = (FIXTURES / "memory_extended" / "recovered.txt").read_bytes()
    (recovered / "recovered.txt").write_bytes(data)
    disk = TARGET / "disk" / "artifacts"
    disk.mkdir(parents=True, exist_ok=True)
    (disk / "a.ps1").write_bytes(data)  # Inert text, never executed.
    for kind in ("mft", "usn", "prefetch", "evtx", "amcache"):
        rows = json.loads((FIXTURES / "disk" / f"{kind}.json").read_text())
        if kind == "mft":
            rows[0]["SHA256"] = hashlib.sha256(data).hexdigest()
            rows[0]["FileSize"] = len(data)
            for index in range(12):
                rows.append(
                    {
                        "EntryNumber": 200 + index,
                        "SequenceNumber": 1,
                        "FileName": "a.ps1",
                        "FullPath": f"D:\\Other\\{index}\\a.ps1",
                        "InUse": True,
                        "Created0x10": "2026-09-16T09:31:26Z",
                        "FixtureRole": "noise",
                    }
                )
        if kind == "prefetch":
            rows[0].pop("PreviousRun0", None)
        if kind == "amcache":
            rows[0]["FileId"] = "0000" + "a" * 40
            rows[0].pop("SHA1", None)
        if kind == "evtx":
            for index in range(8):
                row = dict(rows[0])
                row.update(
                    RecordId=1000 + index,
                    FixtureRole="noise",
                    ParentProcessId=7000 + index,
                    ProcessId=4120 if index < 4 else 9000 + index,
                    TimeCreated="2026-09-16T06:00:00Z" if index < 4 else "2026-09-16T09:31:25Z",
                    CommandLine=f"powershell.exe -File D:\\Other\\{index}\\a.ps1",
                    Computer="other-host" if index >= 4 else "workstation-01",
                )
                rows.append(row)
        save(disk / f"{kind}.json", rows)
    packets = sample_packets()
    for index in range(4):
        packets.append(
            (
                24.9 + index / 100,
                packet(
                    f"192.0.2.{20 + index}",
                    "192.0.2.53",
                    54000 + index,
                    53,
                    dns(domain=f"noise{index}.test"),
                    17,
                ),
            )
        )
    for suffix in ("pcap", "pcapng"):
        write_capture(TARGET / "network" / ("traffic." + suffix), packets, suffix == "pcapng")
    imports = [
        {
            "kind": "memory",
            "path": "memory/volatility",
            "context": {
                "acquisition_id": "cross-memory",
                "recovered_directory": "memory/recovered",
                "tool_version": "2.28.0",
            },
        }
    ]
    imports.extend(
        {"kind": kind, "path": f"disk/artifacts/{kind}.json", "context": {"acquisition_id": "cross-disk"}}
        for kind in ("mft", "usn", "prefetch", "evtx", "amcache")
    )
    imports.extend(
        [
            {
                "kind": "file",
                "path": "disk/artifacts/a.ps1",
                "context": {
                    "acquisition_id": "cross-disk",
                    "logical_path": "C:\\Users\\test\\AppData\\Local\\Temp\\a.ps1",
                },
            },
            {
                "kind": "pcap",
                "path": "network/traffic.pcapng",
                "context": {"acquisition_id": "cross-network", "hostname": None, "tool_version": "4.6.6"},
            },
        ]
    )
    save(
        TARGET / "case.json",
        {
            "name": "Cross-Source Investigation",
            "context": {
                "acquisition_id": "cross-case",
                "extracted_at": "2026-09-16T09:35:00Z",
                "hostname": "workstation-01",
                "volume_id": "volume-C",
                "mount_point": "C:\\",
            },
            "imports": imports,
        },
    )


if __name__ == "__main__":
    generate()
