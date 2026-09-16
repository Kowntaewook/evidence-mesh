# Synthetic sample case

These 15 JSON observations are fictional. No executable, script payload, packet capture, or memory image is included.

| Source | Related event IDs | Noise IDs |
|---|---|---|
| Memory | MEM-EXPLORER, MEM-PS, MEM-SOCKET | NOISE-MEM, NOISE-PID-REUSE |
| Disk | DISK-ZIP, DISK-SCRIPT, DISK-USN, DISK-PREFETCH | NOISE-DISK, NOISE-BASENAME |
| Network | NET-DNS, NET-TLS | NOISE-NET, NOISE-PORT |

Select `MEM-PS` to obtain the 9 related observations and 16 links at the default threshold of 50. Hash `aaaa…` is explicitly synthetic. Artifact identifiers use the `synthetic:` namespace. The address `185.10.10.5` follows the requested example as a literal observation; the application never contacts it. `evil.example` is a sample domain string.

The explorer record and archive record share process identity. PowerShell records explorer as its parent and references the script's full path. MFT and USN observations identify that script; Prefetch references it. The memory socket is owned by the recorded PowerShell process and has the same tuple as the PCAP observation. The DNS observation precedes the connection and resolves to its destination.

These observations illustrate a scenario; correlation does not prove the archive caused execution. `scripts/generate_samples.py` regenerates these fixtures and must not be pointed at real evidence.
