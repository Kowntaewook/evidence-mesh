# EvidenceMesh v0.4 status report — completion pending

This is a progress report, not a completed release claim. Windows execution and
release remain blocked by GitHub integration access to the target repository.

## 1. Version

EvidenceMesh v0.4.0. VERSION, Python/Electron packages, API, parser defaults,
generated version constants and installer filename are synchronized and checked.

## 2. Self-contained Status

Implemented installer design: Python required NO; Node required NO; Volatility
install required NO; TShark install required NO. This intended Windows experience
is **NOT YET VALIDATED**. The actual Linux frozen-backend preflight passed.

## 3. Windows Installer

Filename: `EvidenceMesh.Setup.0.4.0.exe` (configured target).
Size: NOT BUILT. SHA-256: NOT AVAILABLE. Installer E2E: NOT RUN.

## 4. Memory

Raw execution: IMPLEMENTED, fixture subprocess orchestration tested.
Bundled Volatility: packaged and discovered in Linux preflight; Windows pending.
Plugin count: 20 default, plus explicit FILE_OBJECT-selected dumpfiles.
Progress, cancellation, timeout, partial failure, cache, re-run and original-image
provenance are implemented. **NOT VALIDATED WITH REAL MEMORY IMAGE**.

## 5. Disk

MFT: PASS existing synthetic/export tests. USN: PASS v2/v3/v4 generated records,
including opaque 128-bit IDs and v4 extents. Prefetch: PASS SCCA 17/23/26/30/31 and
MAM4 with bounds; MAM 0x84 UNAVAILABLE. EVTX/Amcache: PASS existing public raw and
export compatibility. Raw disk image: PARTIAL, generated read-only NTFS whole
volume/MBR/GPT discovery/extraction tests pass. E01: abstraction present, reader
UNAVAILABLE. Source hashes and derived-artifact lineage are preserved.

## 6. Network

Bundled TShark: pinned 4.6.8 runtime acquired, 40-file PE closure checked;
Windows execution pending. PCAP/PCAPNG, DNS, TCP, UDP, HTTP and TLS metadata:
PASS using actual Linux TShark. HTTP body reassembly/hash and TLS decryption with
matching supplied key: PASS real offline synthetic capture tests. Without keys,
encrypted HTTP is not recovered and remains metadata-only.

## 7. Correlation

Existing correlation rules and regression results are preserved. Recovered HTTP
body File identity uses the existing `same_sha256` rule; no new causation claim
or malware verdict is added. Dedicated kernel ownership scores and case-wide
NAT/clock-offset settings remain PARTIAL/unimplemented.

## 8. UI

Black/red theme retained. Added native memory/disk/key-log selection, plugin
progress/cancel/re-run, read-only volume/artifact selection and dependency status.
Large cases use 100-event server pages; graphs have root/depth/node/type/score
bounds. Actual Linux Electron 10k/50k/100k four-view/next-page smokes passed.

## 9. Tests

Full suite: **288 passed, 0 failed, 0 skipped**, with two dependency warnings.
All original 242 tests and fixture bytes remain intact. Ruff, TypeScript and build
checks passed. Original and new development Electron E2E passed. After the final
logging/process-count fixes, all 48 affected tests passed again. Actual Linux
PyInstaller backend build/imports/data/discovery/health/SQLite/shutdown passed.

## 10. Windows E2E

**NOT RUN.** A test is implemented for silent install, actual installed app,
automatic backend, AppData/SQLite/authenticated health, sample analysis, timeline,
graph/provenance, disk inputs, bundled PATH-independent PCAP/TLS, Volatility
discovery/invocation, clean process exit and silent uninstall. A test definition
is not an executed PASS.

## 11. GitHub Actions

Build: NOT RUN. Installer test: NOT RUN. Release: NOT RUN.
Branch creation for `Kowntaewook/evidence-mesh` returned GitHub 403,
`Resource not accessible by integration`. The connected installation list contains
only the `APEX-digtal-forensic-tool` organization. Repository connection must be
added before authorized publication can proceed.

## 12. Release

v0.4 release: **NOT CREATED**. No downloadable v0.4 installer or hash is claimed.
The configured release assets are the installer, SHA256SUMS.txt, Windows-E2E.json
and the corresponding-source archive. Sources/notices have been acquired locally;
the workflow publishes a draft only after all Windows gates pass and publishes it
publicly only after all assets upload.

## 13. Unsupported

Real memory-image validation; E01 parsing; encrypted/deleted filesystem recovery;
MAM 0x84; arbitrary malformed/incomplete HTTP stream recovery; keyless TLS
decryption; automatic NAT/clock/device mapping; dedicated kernel ownership rules;
live capture; signed Windows binary validation. Windows installer execution and
release are pending external repository access, not marked complete.
