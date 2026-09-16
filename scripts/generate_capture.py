"""Create inert, offline protocol fixtures. No network sockets are opened."""

import ipaddress
import struct
from datetime import datetime
from pathlib import Path

BASE = datetime.fromisoformat("2026-09-16T09:31:00+00:00").timestamp()


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return ~value & 0xFFFF


def packet(src, dst, sport, dport, payload=b"", protocol=6, flags=0x18, sequence=1):
    source, target = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    if protocol == 6:
        transport = struct.pack("!HHIIBBHHH", sport, dport, sequence, 1, 0x50, flags, 65535, 0, 0)
        pseudo = source + target + struct.pack("!BBH", 0, 6, len(transport) + len(payload))
        value = checksum(pseudo + transport + payload)
        transport = transport[:16] + struct.pack("!H", value) + transport[18:]
    else:
        transport = struct.pack("!HHHH", sport, dport, len(payload) + 8, 0)
    length = 20 + len(transport) + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, length, 1, 0, 64, protocol, 0, source, target)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return bytes.fromhex("00112233445566778899aabb0800") + header + transport + payload


def dns(response=False, domain="example.test"):
    name = b"".join(bytes([len(part)]) + part.encode() for part in domain.split(".")) + b"\0"
    query = name + struct.pack("!HH", 1, 1)
    answer = bytes.fromhex("c00c000100010000003c0004") + ipaddress.ip_address("203.0.113.20").packed
    return (
        struct.pack("!HHHHHH", 0x1234, 0x8180 if response else 0x0100, 1, int(response), 0, 0)
        + query
        + (answer if response else b"")
    )


def hello(domain="example.test"):
    server_name = b"\0" + struct.pack("!H", len(domain)) + domain.encode()
    extension = struct.pack("!HHH", 0, len(server_name) + 2, len(server_name)) + server_name
    body = bytes.fromhex("0303") + b"\x01" * 32 + b"\0" + bytes.fromhex("0002002f0100")
    body += struct.pack("!H", len(extension)) + extension
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return bytes.fromhex("160301") + struct.pack("!H", len(handshake)) + handshake


def sample_packets():
    client, server = "10.0.0.5", "203.0.113.20"
    return [
        (24.781, packet(client, "10.0.0.53", 53001, 53, dns(), 17)),
        (24.800, packet("10.0.0.53", client, 53, 53001, dns(True), 17)),
        (26.301, packet(client, server, 51231, 443, flags=2, sequence=0)),
        (26.310, packet(server, client, 443, 51231, flags=0x12, sequence=0)),
        (26.320, packet(client, server, 51231, 443, flags=0x10)),
        (26.350, packet(client, server, 51231, 443, hello())),
        (
            28.001,
            packet(
                client,
                server,
                51232,
                80,
                b"GET /a.txt HTTP/1.1\r\nHost: example.test\r\nUser-Agent: EvidenceMeshFixture\r\n\r\n",
            ),
        ),
        (
            28.050,
            packet(
                server,
                client,
                80,
                51232,
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK",
            ),
        ),
        (31.000, packet("192.0.2.7", "192.0.2.8", 9000, 9001, b"offline fixture", 17)),
    ]


def write_capture(path, packets, pcapng=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as out:
        if not pcapng:
            out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for offset, data in packets:
                timestamp = round((BASE + offset) * 1_000_000)
                out.write(
                    struct.pack("<IIII", timestamp // 1_000_000, timestamp % 1_000_000, len(data), len(data))
                )
                out.write(data)
        else:

            def block(kind, payload):
                padding = b"\0" * (-len(payload) % 4)
                size = len(payload) + len(padding) + 12
                out.write(struct.pack("<II", kind, size) + payload + padding + struct.pack("<I", size))

            block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
            block(1, struct.pack("<HHI", 1, 0, 65535))
            for offset, data in packets:
                timestamp = round((BASE + offset) * 1_000_000)
                block(
                    6,
                    struct.pack("<IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, len(data), len(data))
                    + data,
                )


if __name__ == "__main__":
    for suffix in ("pcap", "pcapng"):
        write_capture(
            Path("tests/fixtures/network") / f"sample.{suffix}", sample_packets(), suffix == "pcapng"
        )
