# EvidenceMesh v0.4 verification — release pending

Date: 2026-09-16. Development environment: Linux ARM64, Python 3.14.6, Node
24.19.0, Electron 44.4.1, TShark 4.6.6, Volatility 3 2.28.0. The baseline is
`ea3cdedc2bb005dd21e0c1771a3caa5b71ed7254` (tag v0.3.1, internal version 0.3.0).
The previous verification report is preserved in `history/VERIFICATION_v03.md`.

## Executed results

| Check | Actual result |
|---|---|
| Baseline Python suite | 242 passed; tests and fixtures retained byte-identical |
| v0.4 full Python suite | 288 passed, 0 failed, 0 skipped; 2 dependency deprecation warnings; 21.92 s |
| Ruff lint / format | PASS |
| Version synchronization | PASS, 0.4.0 |
| TypeScript typecheck / build | PASS |
| Existing Electron development E2E | PASS, sample 15/9/16 and cross-source 67 events / 34 related preserved |
| New native picker/disk/TLS Electron E2E | PASS with real backend and TShark; only native selections supplied by test |
| 10k/50k/100k UI smoke | PASS; Process/Files/Network/Timeline each buffer/render 100 rows, including next page |
| TShark Windows acquisition | PASS archive SHA-256, 40-file PE import/delay-import closure, runtime/data inventory |
| Corresponding source acquisition | PASS, 35 native source archives; 62 total archives including development Python dependencies |
| Linux frozen-backend preflight | PASS: actual PyInstaller build, embedded Python 3.14.7, imports/data, Volatility discovery, health/SQLite and parent-pipe shutdown; system Linux TShark explicitly configured |
| Windows executable / installed E2E | **NOT RUN** |
| GitHub v0.4 release | **NOT CREATED** |

The GitHub connector returned `403 Resource not accessible by integration` on
creating `codex/v0.4.0` in `Kowntaewook/evidence-mesh`. Its installation list contains
the APEX-digtal-forensic-tool organization only. This is an external access block;
no local result substitutes for the required `windows-latest` execution.

## New tests and evidence

- Runtime/raw memory: 10 tests covering argument arrays, real subprocess fixture
  execution, partial errors/unavailable plugins, timeout/cancel, hash cache,
  re-run/provenance, bundled/system/missing decoder lookup, empty-PATH PCAP/PCAPNG,
  dynamic authenticated launcher health/SQLite/shutdown and occupied-port failure.
- Disk formats: 17 tests for SCCA 17/23/26/30/31, compressed/uncompressed fields,
  MAM literal/match/truncated/bounded cases, USN 2/3/4 and opaque 128-bit identities.
- Raw NTFS: 6 tests parse generated actual filesystem bytes in superfloppy, MBR
  and GPT containers; selected extraction, immutable source hash, lineage,
  partial corruption, unavailable E01 and case-scoped API are checked.
- Network: 9 tests use actual TShark for split Content-Length/chunked request and
  response bodies in both capture formats, disk hash correlation and a real
  offline TLS 1.2 exchange with/without supplied session keys.
- Bounded views: 4 tests cover page/search/isolation, graph limits and score/type
  filters, bounded analysis results and 100k-row queries deserializing only 100.

Logs: `data/pytest-v04-packaging.log`, `data/e2e-v04-paging-regression.log`,
`data/e2e-v04-disk-network-performance.log`, `data/source-bundle-full.log`,
`data/pyinstaller-linux-preflight.log`, `data/backend-frozen-linux-smoke.log`.
After logging/process-count changes, the 48 affected view/disk tests passed again.
The UI four-view loops took 970 / 1467 / 2307 ms for 10k / 50k / 100k in one Linux
run. These are smoke observations, not universal performance guarantees or
Windows measurements. Original backend benchmarks are retained in the historical
report; they do not measure raw-image parsing or dense all-to-all graphs.

## Pending Windows gate

The workflow and `desktop/tests/installed-windows.cjs` are implemented. Required
execution: NSIS silent install, installed app path/version, automatic frozen
backend, authenticated health/SQLite/AppData, sample correlation/provenance/
timeline/graph, binary disk formats and NTFS extraction, PCAP and PCAPNG
DNS/TCP/UDP/HTTP/TLS using the installed decoder with restricted PATH, real
supplied-key TLS body recovery, actual Volatility plugin discovery and invalid
image invocation, clean app/backend/worker exit, closed port and silent uninstall.
The test emits `Windows-E2E.json`, screenshots and logs; no PASS is recorded until
the assertions actually execute.

## Explicit limits

**NOT VALIDATED WITH REAL MEMORY IMAGE.** Raw execution exists; real-image
validation was excluded. E01 parsing, encrypted/deleted disk recovery, MAM 0x84,
automatic NAT/clock correction/device mapping and dedicated kernel ownership
scores remain unavailable/partial as documented. TLS needs matching supplied key
material. Malformed/incomplete HTTP streams remain best-effort, bounded at 32 MiB
per body. Windows signing is optional; no signed binary is claimed.
