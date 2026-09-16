"""Rebuild explicitly synthetic sample JSON. Never run on real evidence directories."""

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples" / "sample_case"
HOST = "workstation-01"
SCRIPT = r"C:\Users\test\AppData\Local\Temp\a.ps1"
EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
ZIP = r"C:\Users\test\Downloads\invoice.zip"
PS = {
    "pid": 4120,
    "ppid": 2032,
    "name": "powershell.exe",
    "path": EXE,
    "command_line": f'powershell.exe -File "{SCRIPT}"',
    "creation_time": "2026-09-16T09:31:25Z",
}
EXPLORER = {
    "pid": 2032,
    "ppid": 800,
    "name": "explorer.exe",
    "path": r"C:\Windows\explorer.exe",
    "creation_time": "2026-09-16T09:31:20Z",
}
SOCKET = {
    "src_ip": "192.168.0.15",
    "src_port": 50321,
    "dst_ip": "185.10.10.5",
    "dst_port": 443,
    "protocol": "TCP",
}


def event(identifier, source, kind, second, artifact, **fields):
    return {
        "event_id": identifier,
        "timestamp": f"2026-09-16T09:31:{second}Z",
        "source": source,
        "type": kind,
        "hostname": HOST,
        "source_artifact": {
            "artifact_id": f"synthetic:{artifact}",
            "kind": artifact,
            "path": f"synthetic://sample/{artifact}",
        },
        "parser": {"name": "synthetic-fixture", "version": "0.1.0"},
        "raw_reference": {"artifact_id": f"synthetic:{artifact}", "locator": identifier},
        "attributes": {"synthetic": True},
        **fields,
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    memory = [
        event("MEM-EXPLORER", "memory", "process_start", "20.000", "memory-export", process=EXPLORER),
        event(
            "MEM-PS",
            "memory",
            "process_start",
            "25.000",
            "memory-export",
            process=PS,
            user={"name": "test", "sid": "S-1-5-21-1000"},
        ),
        event("MEM-SOCKET", "memory", "socket", "29.300", "memory-export", process=PS, network=SOCKET),
        event(
            "NOISE-MEM",
            "memory",
            "process_start",
            "25.100",
            "memory-export",
            process={"pid": 9000, "name": "notepad.exe", "creation_time": "2026-09-16T09:31:25.100Z"},
        ),
        event(
            "NOISE-PID-REUSE",
            "memory",
            "process_start",
            "25.200",
            "memory-export",
            process={
                **PS,
                "creation_time": "2026-09-15T09:31:25Z",
                "ppid": None,
                "command_line": "powershell.exe",
            },
        ),
    ]
    disk = [
        event("DISK-ZIP", "disk", "file_created", "21.000", "$MFT", process=EXPLORER, file={"path": ZIP}),
        event(
            "DISK-SCRIPT", "disk", "file_created", "25.800", "$MFT", file={"path": SCRIPT, "sha256": "a" * 64}
        ),
        event(
            "DISK-USN",
            "disk",
            "file_modified",
            "26.000",
            "$UsnJrnl",
            file={"path": SCRIPT, "sha256": "a" * 64},
        ),
        event(
            "DISK-PREFETCH",
            "disk",
            "prefetch",
            "27.000",
            "Prefetch",
            file={"path": r"C:\Windows\Prefetch\POWERSHELL.EXE-12345678.pf", "references": [EXE, SCRIPT]},
        ),
        event("NOISE-DISK", "disk", "file_modified", "25.700", "$MFT", file={"path": r"C:\Temp\notes.txt"}),
        event(
            "NOISE-BASENAME", "disk", "file_created", "25.800", "$MFT", file={"path": r"D:\Unrelated\a.ps1"}
        ),
    ]
    network = [
        event(
            "NET-DNS",
            "network",
            "dns_query",
            "28.100",
            "PCAP",
            network={
                "src_ip": "192.168.0.15",
                "dst_ip": "192.168.0.1",
                "src_port": 51000,
                "dst_port": 53,
                "protocol": "UDP",
                "dns_query": "evil.example",
                "resolved_ips": ["185.10.10.5"],
            },
        ),
        event("NET-TLS", "network", "network_connection", "29.500", "PCAP", network=SOCKET),
        event(
            "NOISE-NET",
            "network",
            "network_connection",
            "29.510",
            "PCAP",
            network={
                "src_ip": "192.168.0.15",
                "src_port": 62000,
                "dst_ip": "203.0.113.10",
                "dst_port": 443,
                "protocol": "TCP",
            },
        ),
        event(
            "NOISE-PORT",
            "network",
            "network_connection",
            "29.510",
            "PCAP",
            network={**SOCKET, "dst_port": 8443, "src_ip": "192.168.0.16"},
            hostname="workstation-02",
        ),
    ]
    for source, records in (("memory", memory), ("disk", disk), ("network", network)):
        (OUT / f"{source}_events.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
