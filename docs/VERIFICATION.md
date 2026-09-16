# EvidenceMesh v0.3 verification — 2026-09-16

This is the current local verification record. [v0.2 history](history/VERIFICATION_v02.md) is retained separately and does not describe current support. PASS below refers to an executed check, not a planned CI job.

## Environment and baseline

Linux ARM64 container, Python 3.14.6, Node 24.19.0, Electron 44.4.1, TypeScript 7.0.2, tshark 4.6.6, Volatility 3 2.28.0, python-evtx 0.8.1, dissect.ntfs 3.16 and dissect.regf 3.14. Local memory limit: 8 GiB.

The original 102 tests and their conftest were not edited, deleted or weakened. The source archive/hashes are in `data/baseline-v02/`; a regression test checks original test-file hashes. Original five-plugin import: **14 rows → 8 Events**. Original sample: **15 Events → 9 related → 16 correlations**.

## Automated checks

| Check | Executed result | Evidence |
|---|---|---|
| Editable dev installation | PASS | data/install-v03.log |
| Python suite | **242 passed, 0 failed, 0 skipped** | data/pytest-v03-final.log |
| Original tests | 102 preserved and passing | baseline hash regression + original files |
| Added tests | 140 passing | 53 memory, 44 disk, 18 network, 9 integration, 16 compatibility |
| Ruff lint / format | PASS | direct local execution |
| TypeScript typecheck / build | PASS | npm commands and E2E build |
| Electron package | PASS, Linux ARM64 | data/package-v03-final.log |
| Development Electron E2E | PASS | data/e2e-dev-v03.log |
| Packaged Electron E2E | PASS | data/e2e-packaged-v03.log |
| Live CLI workflow | PASS, 13 commands | data/cli-verification-v03/commands.json |
| Live Uvicorn API | PASS, 24 HTTP calls | data/live-api-v03-report.json |
| Python wheel/sdist build | PASS | data/build-v03.log |
| Independent wheel execution | PASS: clean venv, outside checkout, included 67-Event case | data/wheel-v03-report.json |

The suite emitted two dependency deprecation warnings (Starlette/httpx and AnyIO BlockingPortal); no test was skipped in this environment. Optional-tool/public-file tests can skip on a clean machine lacking their prerequisites; zero skips is not promised there. Remote GitHub Actions was **NOT EXECUTED**.

## Cross-source evidence chain

The fixture contains **67 Events**: memory 24, disk 26, network 17. PID 4120 has **34 related Events and 259 correlations**. **29 explicitly labeled noise observations** stay outside the component; four additional kernel observations also remain unrelated.

Verified chain: PowerShell command-line and handle → a.ps1 FILE_OBJECT/recovered bytes → matching disk content SHA-256, MFT record/sequence, USN, Prefetch and registry-derived evidence; memory socket → PCAP flow → DNS example.test and TLS SNI → 203.0.113.20:443. Exact matching facts, negative gates and source references remain visible. The fixture is synthetic and recovered content is inert.

The live API root graph had 66 nodes/373 edges. Full-case graph tests also verify kernel/driver nodes and all required typed storage tables. Entity edge counts reflect coalesced repeated observations, not deduplicated Event correlations.

## CLI and live API

All 13 explicit CLI commands completed with exit 0: case creation, Memory, MFT, USN, Prefetch, EVTX, Amcache, content file, PCAPNG, correlation, timeline, graph and parser-runs. SQLite case ID: `86119596-f644-4aa8-8148-5373676d4091`. Original CLI tests remain passing.

Actual Uvicorn ran on 127.0.0.1:8765 with a separate SQLite DB. Case `2cdd971c-9284-4044-9029-d5d594e37ad6` imported all sources, returned 28 successful parser runs, and served Events/processes/files/network/correlations/timeline/graph/imports/runs. Pagination and Disk/DNS timeline filters were called. Input SHA-256 values were unchanged after import. All 24 method/route/status records are in the report.

## Desktop E2E

Both development and packaged Linux ARM64 runs use actual Electron, Uvicorn, SQLite and tshark. The test substitutes only native file-picker selections. No API response or evidence table is mocked.

The script preserves the original sample/no-match/JSON/Volatility/provenance/keyboard assertions and additionally creates a case, imports eight artifact inputs, verifies 67 Events and 28 successful runs, selects PID 4120, verifies 34 related Events, opens Memory/Disk/Network process details, checks scores/reasons/frame provenance, filters timeline, selects typed graph relationships, checks exact 64-bit handle/raw values, and imports an invalid capture to inspect its FAILED run. Tables are bounded to 100 rendered rows.

28 screenshots are retained under `desktop/test-results/`, including [cross-source graph](../desktop/test-results/20-cross-source-entity-graph.png), [process disk details](../desktop/test-results/17-process-disk.png) and [parser failure](../desktop/test-results/24-parser-failure.png). These three final packaged captures were also visually inspected. Screenshots/logs/builds are ignored generated artifacts, not committed source.

## Performance

Each benchmark ran in its own process against synthetic normalized Events. The dataset contains repeated small relevant groups plus noise with separated host/process/path/time context.

| Events | Import s | Correlate s | Persist correlations s | Peak MiB | SQLite bytes | Correlations | Candidates / all pairs |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 10,000 | 1.605 | 0.986 | 3.948 | 177.50 | 62,017,536 | 20,000 | 21,000 / 49,995,000 |
| 50,000 | 7.585 | 5.903 | 12.978 | 733.89 | 310,099,968 | 100,000 | 105,000 / 1,249,975,000 |
| 100,000 | 14.522 | 11.804 | 28.229 | 1,425.45 | 620,584,960 | 200,000 | 210,000 / 4,999,950,000 |

Reports: `data/benchmarks-v03-final/{10000,50000,100000}.json`. Import time covers normalized Event storage; raw decoding, graph generation and UI rendering are excluded. Correlation computation and persistence are separately timed. Peak RSS covers the whole benchmark process. SQLite size is measured after WAL checkpoint. Dense identity groups can still produce many output edges; these numbers are not universal complexity or performance guarantees.

A separate real-capture index check built 40,691 candidate pairs for 39,929 Events versus 797,142,556 possible pairs, in approximately 0.654 seconds. That check did not time full correlation.

## Real-data validation: PARTIALLY VALIDATED

| Input | Actual observed result | Scope |
|---|---|---|
| Installed Volatility JsonRenderer | PASS on synthetic TreeGrid nested/time/null/integer fields | Real renderer, not image/plugin execution |
| amcache-new.hve | SUCCESS, 222 Events | Public Dissect binary fixture |
| amcache-old.hve | SUCCESS, 69 Events | Public Dissect binary fixture |
| Security.evtx | SUCCESS, 759 Events | Public Dissect binary fixture |
| TestLogX.evtx | SUCCESS, 5 Events | Public Dissect binary fixture |
| MPCMDRUN.EXE-962E6200.pf | UNAVAILABLE, compressed MAM | Correctly recorded unsupported format |
| shark_is_sniffing.pcap | SUCCESS, 20,000 packets → 39,929 Events | Existing workspace capture |
| cats_fragments.pcap | SUCCESS, 2,826 packets → 7 flows | Existing workspace capture |
| Raw MFT / USN / SCCA | Synthetic binary tests pass | Real image NOT VALIDATED |
| Raw memory image | **NOT VALIDATED WITH REAL IMAGE** | No suitable image available |

Public sources: [Fox-IT Dissect test artifacts](https://github.com/fox-it/dissect.target/tree/main/tests/_data/plugins/os/windows). Exact download URLs, sizes and SHA-256 are in `data/compatibility/sources.json`; run results are in disk-results.json/network-results.json. Test corpus and workspace-capture collection history do not establish independently verified incident ground truth.

## Limitations and unsupported work

MAM Prefetch, USN v3/v4, raw memory/plugin/extraction automation, whole disk image mounting, deleted registry recovery/transaction-log replay, TLS decryption and HTTP body-to-file causation are unsupported. Kernel driver/callback scored correlation is partial. No automatic NAT, clock-skew or device-volume mapping is performed.

DOM pagination and graph caps are implemented, but the renderer holds a complete loaded case and no 100k-event UI benchmark is claimed. The package requires a separate Python backend and external tools. Windows/macOS packaging, signing/installers and remote CI are not validated.

## Commands actually executed

The checkout Python executable is `.venv/bin/python`; virtualenv scripts were used for pytest/ruff. Logs and JSON records retain outputs. The commands below describe successful final checks; earlier diagnostics and exploratory failing dependency checks are not advertised as PASS.

```bash
cd /workspace/evidence-mesh
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python scripts/export_schemas.py
.venv/bin/python -m build
.venv/bin/python -m engine.cli discover-plugins
.venv/bin/python scripts/benchmark.py --count 10000 --output data/benchmarks-v03-final
.venv/bin/python scripts/benchmark.py --count 50000 --output data/benchmarks-v03-final
.venv/bin/python scripts/benchmark.py --count 100000 --output data/benchmarks-v03-final
EVIDENCEMESH_DB=data/live-api-v03.sqlite3 .venv/bin/python -m uvicorn api.main:app --host 127.0.0.1 --port 8765
cd desktop
npm run typecheck
npm run build
npm run package
xvfb-run -a -s '-screen 0 1600x1100x24' npm run test:e2e
EVIDENCEMESH_DESKTOP_EXECUTABLE="$PWD/release/EvidenceMesh-linux-arm64/EvidenceMesh" xvfb-run -a -s '-screen 0 1600x1100x24' npm run test:e2e
```

The exact 13 CLI argument arrays follow. Independent wheel install/execution commands and resolved paths are retained in `data/wheel-v03-report.json`; live HTTP method/routes are retained in `data/live-api-v03-report.json`.

```bash
/workspace/evidence-mesh/.venv/bin/python -m engine.cli case-create --name 'Final CLI Cross-Source' --db data/cli-verification-v03/case.sqlite3
/workspace/evidence-mesh/.venv/bin/python -m engine.cli import memory /workspace/evidence-mesh/samples/cross_source/memory/volatility --db data/cli-verification-v03/case.sqlite3 --case-id 86119596-f644-4aa8-8148-5373676d4091 --acquisition-id cross-memory --extracted-at 2026-09-16T09:35:00Z --hostname workstation-01 --volume-id volume-C --mount-point 'C:\' --recovered-directory /workspace/evidence-mesh/samples/cross_source/memory/recovered --tool-version 2.28.0
/workspace/evidence-mesh/.venv/bin/python -m engine.cli import mft /workspace/evidence-mesh/samples/cross_source/disk/artifacts/mft.json --db data/cli-verification-v03/case.sqlite3 --case-id 86119596-f644-4aa8-8148-5373676d4091 --acquisition-id cross-disk --extracted-at 2026-09-16T09:35:00Z --hostname workstation-01 --volume-id volume-C --mount-point 'C:\'
/workspace/evidence-mesh/.venv/bin/python -m engine.cli import usn /workspace/evidence-mesh/samples/cross_source/disk/artifacts/usn.json --db data/cli-verification-v03/case.sqlite3 --case-id 86119596-f644-4aa8-8148-5373676d4091 --acquisition-id cross-disk --extracted-at 2026-09-16T09:35:00Z --hostname workstation-01 --volume-id volume-C --mount-point 'C:\'
/workspace/evidence-mesh/.venv/bin/python -m engine.cli import prefetch /workspace/evidence-mesh/samples/cross_source/disk/artifacts/prefetch.json --db data/cli-verification-v03/case.sqlite3 --case-id 86119596-f644-4aa8-8148-5373676d4091 --acquisition-id cross-disk --extracted-at 2026-09-16T09:35:00Z --hostname workstation-01 --volume-id volume-C --mount-point 'C:\'
/workspace/evidence-mesh/.venv/bin/python -m engine.cli import evtx /workspace/evidence-mesh/samples/cross_source/disk/artifacts/evtx.json --db data/cli-verification-v03/case.sqlite3 --case-id 86119596-f644-4aa8-8148-5373676d4091 --acquisition-id cross-disk --extracted-at 2026-09-16T09:35:00Z --hostname workstation-01 --volume-id volume-C --mount-point 'C:\'
/workspace/evidence-mesh/.venv/bin/python -m engine.cli import amcache /workspace/evidence-mesh/samples/cross_source/disk/artifacts/amcache.json --db data/cli-verification-v03/case.sqlite3 --case-id 86119596-f644-4aa8-8148-5373676d4091 --acquisition-id cross-disk --extracted-at 2026-09-16T09:35:00Z --hostname workstation-01 --volume-id volume-C --mount-point 'C:\'
/workspace/evidence-mesh/.venv/bin/python -m engine.cli import file /workspace/evidence-mesh/samples/cross_source/disk/artifacts/a.ps1 --db data/cli-verification-v03/case.sqlite3 --case-id 86119596-f644-4aa8-8148-5373676d4091 --acquisition-id cross-disk --extracted-at 2026-09-16T09:35:00Z --hostname workstation-01 --volume-id volume-C --mount-point 'C:\' --logical-path 'C:\Users\test\AppData\Local\Temp\a.ps1'
/workspace/evidence-mesh/.venv/bin/python -m engine.cli import pcap /workspace/evidence-mesh/samples/cross_source/network/traffic.pcapng --db data/cli-verification-v03/case.sqlite3 --case-id 86119596-f644-4aa8-8148-5373676d4091 --acquisition-id cross-network --extracted-at 2026-09-16T09:35:00Z --volume-id volume-C --mount-point 'C:\' --tool-version 4.6.6
/workspace/evidence-mesh/.venv/bin/python -m engine.cli correlate --db data/cli-verification-v03/case.sqlite3 --case-id 86119596-f644-4aa8-8148-5373676d4091
/workspace/evidence-mesh/.venv/bin/python -m engine.cli timeline --db data/cli-verification-v03/case.sqlite3 --case-id 86119596-f644-4aa8-8148-5373676d4091
/workspace/evidence-mesh/.venv/bin/python -m engine.cli graph --db data/cli-verification-v03/case.sqlite3 --case-id 86119596-f644-4aa8-8148-5373676d4091
/workspace/evidence-mesh/.venv/bin/python -m engine.cli parser-runs --db data/cli-verification-v03/case.sqlite3 --case-id 86119596-f644-4aa8-8148-5373676d4091
```
