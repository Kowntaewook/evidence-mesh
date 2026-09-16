# EvidenceMesh v0.4.0

Windows x64 installer with embedded Python/FastAPI, Volatility 3 and offline
TShark. Python, Node.js, Volatility and Wireshark do not need a separate install.
Dynamic loopback backend startup, dependency diagnostics, logs, cancellation and
clean shutdown are managed by the desktop application.

Supported inputs include Volatility JSON exports and raw-memory orchestration,
MFT, USN 2/3/4, SCCA Prefetch 17/23/26/30/31 with MAM4 decompression, EVTX, Amcache,
read-only raw NTFS images and PCAP/PCAPNG. Plain HTTP bodies are recovered and
hashed; TLS decryption requires a supplied session key log. Existing correlation,
reasons, provenance, incident graph and timeline remain available. Large-case
tables use bounded pages and graphs have depth/node/score/type limits.

Requirements: Windows 10/11 x64, sufficient space for the application and derived
evidence. The installer is unsigned unless the build has signing secrets; Windows
SmartScreen may display a warning. No live capture driver is included.

Raw memory execution is implemented, but **NOT VALIDATED WITH REAL MEMORY IMAGE**.
Volatility may require matching symbols for an actual image. E01 containers remain
UNAVAILABLE behind an adapter abstraction; encrypted or unsupported disk layouts,
MAM variants other than MAM4, malformed streams and incomplete captures can remain
partial or unavailable. TLS without keys provides metadata only. Parser findings
are evidence observations, not malware verdicts.

The release is gated on Python/Ruff/Electron checks and a real Windows silent
install → installed application/backend → sample/correlation/timeline/graph →
disk and bundled PCAP/TLS imports → clean shutdown → uninstall. See
`Windows-E2E.json` for the executed checks and `SHA256SUMS.txt` for asset hashes.
The corresponding-source archive and license notices accompany the installer.
