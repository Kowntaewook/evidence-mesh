# Synthetic cross-source case

Regenerate with `python scripts/generate_cross_source.py`. The case contains 21
Volatility JSON exports, five disk artifact exports, inert recovered text and actual
PCAP/PCAPNG containers. The script file contains only fixture text and is never run.
`case.json` uses relative inputs and explicit acquisition context.

The selected PowerShell process references `a.ps1`, has a file handle and a memory
socket matching the capture. Disk MFT/USN/Prefetch and DNS/TLS corroborate those facts.
Noise includes 12 same-name files at different paths, eight other process lifetimes
or hosts, four unrelated DNS clients and an unrelated UDP flow. This dataset is
synthetic; it does not establish real-image compatibility.
