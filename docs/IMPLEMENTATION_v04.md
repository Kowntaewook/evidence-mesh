# v0.4 implementation audit

Authoritative request: attachment 5e12444b-8255-41e7-9048-57e7bc3be63c/pasted-text-1.txt (57 sections).
Baseline: ea3cded (tag v0.3.1); internal version 0.3.0; 242 passing tests, 2 dependency warnings. Tracked source hashes: data/baseline-v031/sha256.json. Existing tests remain unchanged. User-provided release-v0.3.1 installer is preserved.

| Sections | Requirement | Current evidence / completion gate |
|---|---|---|
| 1–3 | One-installer UX, baseline, unified 0.4.0 | Baseline captured; VERSION sync/check implemented and passed; installer gate pending |
| 4–6 | Embedded backend, lifecycle, dynamic loopback port | Implemented dynamic port, session authentication, health/start/quit/logging; development launcher tests pass; Windows executable gate pending |
| 7–9 | Bundled TShark, licenses, PATH-independent PCAP | Pinned 4.6.8 acquired and PE closure checked; 35 native source archives + Python sources/notices bundled; actual Windows execution pending |
| 10–15 | Raw memory orchestration/progress/cancel/cache/provenance | Implemented 20 default plugins, explicit dumpfiles, progress/cancel/cache/partial outcomes; subprocess fixture tests pass; real image NOT VALIDATED |
| 16–18 | MAM/SCCA and USN v3/v4 | PASS generated MAM4, SCCA 17/23/26/30/31, USN 2/3/4, bounds/128-bit IDs; MAM 0x84 explicitly UNAVAILABLE |
| 19–22 | Read-only raw disk, E01 abstraction, volumes UI, derived lineage | PASS synthetic NTFS whole-volume/MBR/GPT extraction, native picker/volume tree/selection, original hashes and lineage; E01 reader UNAVAILABLE behind container abstraction |
| 23–24 | HTTP bodies and optional supplied TLS keys | PASS actual TShark split Content-Length/chunked request/response recovery + SHA-256; real offline TLS MemoryBIO capture stays metadata-only without key and yields body with supplied key; native key picker E2E PASS |
| 25–28 | Explicit host/NAT/clock/volume context and kernel reasons | PARTIAL: existing explicit import host/timezone/volume context retained; case NAT/source clock-offset settings and dedicated kernel ownership rules are not implemented |
| 29–30 | Bounded loading and graph queries | Implemented server event pages, bounded graph adjacency/depth/type/score/node limit, bounded analysis responses; 100k page deserializes only 100 rows; actual Electron 10k/50k/100k pages PASS |
| 31–34 | Actual installed Windows E2E and bundled runtimes | REQUIRED GitHub Actions windows-latest silent install/start/sample/PCAP/quit/uninstall |
| 35–40 | User-data paths, logs, diagnostics, dependency status, security, optional signing | Implemented AppData paths, rotating backend logs, startup/crash diagnostics, runtime status, token/IPC security, optional signing and Windows Job Object; Windows runtime gate pending |
| 41–45 | Gated tag release, assets/hash/notes/download links | Implemented fail-closed build/E2E/source/hash/draft-release workflow; actual publication blocked by GitHub integration 403 |
| 46–47 | Honest support matrix, Windows-only distribution scope | Updated documented PASS/PARTIAL/NOT VALIDATED/UNAVAILABLE matrix and Windows distribution scope |
| 48–51 | Added regression/packaging/format tests, workflow gates, performance | 288 pytest PASS, Ruff/TypeScript/build PASS, original and new Electron smokes PASS; Windows gate not run |
| 52–55 | All named docs and limitations, actual validation, invariants | All named documents updated; pending Windows fields remain explicitly NOT RUN |
| 56–57 | Completion criteria and 13-part final report | Unproven until Windows installer E2E and release are inspected |

Publication block: Git CLI credentials are unavailable. The GitHub connector can read the public repository, but create_branch for Kowntaewook/evidence-mesh returned 403 Resource not accessible by integration. list_installations shows only APEX-digtal-forensic-tool (installation 147152166). The user has been asked to add the Kowntaewook repository connection; no alternate-account write is attempted.

## Executed development evidence

- Original 242 tests and all original test fixtures verified byte-identical to tag v0.3.1.
- `data/pytest-v04-disk.log`: 275 passed after disk additions.
- `data/e2e-v04-paging-regression.log`: original Electron E2E PASS, including 67 cross-source events / 34 related observations and original sample 16 links / 9 events.
- `data/e2e-v04-disk-network-performance.log`: native disk/key-log picker flows PASS; 10k / 50k / 100k process/files/network/timeline each buffer 100 events, including next-page checks. Timings for the four-view loop: 970 / 1467 / 2307 ms in this Linux development run. These are smoke observations, not Windows benchmark claims.
- `tests/test_views_v04.py`: 4 tests passed, including 100k-row deserialization bound and graph queries that fail if whole-case repository loaders are called.
- Windows packaged execution, installer E2E and v0.4 release are **NOT YET RUN**.

Current disk bounds: 2 GiB per extracted artifact, 4 million MFT records and 20k discovered artifacts; allocated standard NTFS artifact paths only, no deleted-file carving, extended MBR, encryption or E01 parsing. HTTP body recovery is bounded at 32 MiB and preserves content encoding; multiple bodies in a single decoded packet are reported as ambiguous instead of guessed.


## Packaging preflight

- `data/pytest-v04-packaging.log`: 288 passed, 0 failed/skipped, 2 dependency warnings.
- `data/pytest-v04-final-fixes.log`: 48 view/disk tests passed after logging and process-count correction.
- `data/source-bundle-full.log`: 62 source archives acquired (35 native plus local Python dependency sources), original licenses collected.
- `data/pyinstaller-linux-preflight.log`: actual Linux ARM64 frozen backend built; this is not a Windows executable.
- `data/backend-frozen-linux-smoke.log`: packaged imports/data, actual Volatility discovery, health, SQLite and parent-pipe shutdown PASS. Linux system TShark was explicitly configured for this check; it does not establish the Windows TShark bundle's execution.
- `desktop/tests/installed-windows.cjs` and the windows-latest workflow are ready but have not executed.
