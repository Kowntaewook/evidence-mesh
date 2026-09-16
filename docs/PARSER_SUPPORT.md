# Parser support matrix — v0.4

PASS means implemented and tested **within the input scope stated here**. It does not mean every OS/tool version or real-image scenario was validated. PARTIAL means the described subset is implemented. UNAVAILABLE means the runtime format/dependency cannot be used. NOT VALIDATED means the claimed environment/input has not been executed.

Runtime ParserRun statuses are separate: SUCCESS, FAILED, UNAVAILABLE, SKIPPED, TIMEOUT and CANCELLED; active jobs also have PENDING/RUNNING states. A successful import with sparse fields is not a claim of complete forensic interpretation.

## Memory: existing Volatility JSON exports

All rows: Parse/Normalize/Provenance/Test PASS for documented synthetic export fixtures. Installed Volatility 2.28.0 discovery found all 21. Raw execution is IMPLEMENTED through 20 default plugins plus explicit dumpfiles; it is **NOT VALIDATED WITH REAL MEMORY IMAGE**.

| Plugin (windows.) | Parse | Normalize | Provenance | Correlation | Test | Notes |
|---|---|---|---|---|---|---|
| pslist | PASS | PASS | PASS | PASS | PASS | 기존 active process 병합 유지 |
| pstree | PASS | PASS | PASS | PASS | PASS | scoped parent/child |
| cmdline | PASS | PASS | PASS | PASS | PASS | 명령행 경로 참조 |
| netscan | PASS | PASS | PASS | PASS | PASS | PCAP 5-tuple / interval |
| dlllist | PASS | PASS | PASS | PASS | PASS | process/file/module |
| psscan | PASS | PASS | PASS | PASS | PASS | 별도 observation; pslist 비교 signal |
| envars | PASS | PASS | PASS | PASS | PASS | process 환경 변수 |
| handles | PASS | PASS | PASS | PASS | PASS | raw type / FILE_OBJECT / OPENED |
| filescan | PASS | PASS | PASS | PASS | PASS | FILE_OBJECT / path |
| vadinfo | PASS | PASS | PASS | PASS | PASS | process / region 관측 |
| malware.malfind | PASS | PASS | PASS | PASS | PASS | suspicious_memory_region; 악성 판정 없음 |
| svcscan | PASS | PASS | PASS | PASS | PASS | service/binary/process |
| svclist | PASS | PASS | PASS | PASS | PASS | 설치된 2.28.0에서 available |
| registry.amcache | PASS | PASS | PASS | PASS | PASS | source=memory; disk path corroboration |
| registry.userassist | PASS | PASS | PASS | PASS | PASS | registry/file/process 경로 |
| shimcachemem | PASS | PASS | PASS | PASS | PASS | registry/file 경로 |
| modules | PASS | PASS | PASS | PARTIAL | PASS | path 연관 / modscan 비교; 전용 kernel ownership 점수 없음 |
| modscan | PASS | PASS | PASS | PARTIAL | PASS | path 연관 / modules 비교; 불일치 판정 없음 |
| driverscan | PASS | PASS | PASS | PARTIAL | PASS | 정규화·graph 관측; 전용 scored 관계 미구현 |
| callbacks | PASS | PASS | PASS | PARTIAL | PASS | 정규화·graph 관측; 전용 scored 관계 미구현 |
| dumpfiles | PASS | PASS | PASS | PASS | PASS | 기존 recovered bytes 검증·SHA-256; raw 실행은 명시적 FILE_OBJECT 선택 필요 |

## Disk

| Input | Parse | Normalize | Provenance | Correlation | Test | Notes |
|---|---|---|---|---|---|---|
| MFT JSON/CSV | PASS | PASS | PASS | PASS | PASS | Tested aliases / record+sequence+volume |
| Raw MFT | PASS | PASS | PASS | PASS | PASS | Synthetic FILE records; real image NOT VALIDATED |
| USN JSON/CSV | PASS | PASS | PASS | PASS | PASS | Reason/reference preservation |
| Raw USN v2 | PASS | PASS | PASS | PASS | PASS | Synthetic binary; MFT enrichment |
| Raw USN v3/v4 | PASS | PASS | PASS | PARTIAL | PASS | Opaque 128-bit IDs and v4 extents retained; no fabricated v4 name/time |
| Prefetch JSON/CSV | PASS | PASS | PASS | PASS | PASS | Executable, run times and references |
| Raw SCCA Prefetch | PASS | PASS | PASS | PASS | PASS | Generated raw/compressed tests for 17/23/26/30/31 |
| Raw MAM Prefetch | PARTIAL | PASS | PASS | PASS | PASS | MAM4 supported with bounds; 0x84/unknown variants UNAVAILABLE |
| EVTX raw/XML/exports | PASS | PASS | PASS | PASS | PASS | Public raw files 759/5 Events; specialized provider subset |
| Amcache raw/exports | PASS | PASS | PASS | PASS | PASS | Public modern/legacy hives 222/69 Events |
| Content file | PASS | PASS | PASS | PASS | PASS | Actual SHA-256; explicit original logical path |
| Raw NTFS whole-volume/MBR/GPT | PARTIAL | PASS | PASS | PASS | PASS | Read-only allocated MFT/USN/Prefetch/EVTX/Amcache discovery; generated-image tests |
| E01 / deleted-cell recovery | UNAVAILABLE | UNAVAILABLE | PARTIAL | UNAVAILABLE | PASS | Explicit E01 stream abstraction only; damaged/deleted carving unsupported |

Raw-reader PASS is scoped to the tests above, not a claim of general damaged-image recovery. EVTX categories outside specialized mappings remain generic observations. Amcache execution causation is not asserted.

## Network

| Input / protocol | Parse | Normalize | Provenance | Correlation | Test | Notes |
|---|---|---|---|---|---|---|
| PCAP | PASS | PASS | PASS | PASS | PASS | Actual tshark binary decoding |
| PCAPNG | PASS | PASS | PASS | PASS | PASS | Actual binary fixture |
| DNS | PASS | PASS | PASS | PASS | PASS | A/AAAA, wire response direction, client context |
| TCP | PASS | PASS | PASS | PASS | PASS | Bidirectional stream/tuple, intervals/counts/flags |
| UDP | PASS | PASS | PASS | PASS | PASS | Bidirectional tuple/stream |
| HTTP | PASS | PASS | PASS | PASS | PASS | Visible request/response metadata; flow correlation |
| TLS | PASS | PASS | PASS | PASS | PASS | Observed ClientHello/SNI/version; optional supplied-key decryption |
| Missing tshark | UNAVAILABLE | UNAVAILABLE | PARTIAL | UNAVAILABLE | PASS | Explicit status; never empty success |
| HTTP request/response bodies | PARTIAL | PASS | PASS | PASS | PASS | Content-Length/chunked reassembly, derived SHA-256, existing hash correlation |
| TLS with supplied key log | PARTIAL | PASS | PASS | PASS | PASS | Real offline TLS fixture; no HTTP body without key, actual expected bytes with key |
| Windows bundled TShark | IMPLEMENTED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | Pinned runtime acquired; installed Windows E2E pending |

## System boundaries

Indexed default correlation, negative reasons/lifetime gates, additive SQLite migration, CLI/local API, native Desktop imports, process details, parser audit, typed graph and filtered timeline are implemented and exercised.

Large-case server paging and bounded graph queries are implemented; actual Linux Electron 10k/50k/100k four-view paging smoke passed. Windows self-contained packaging and installed E2E are IMPLEMENTED but NOT VALIDATED: GitHub repository writes currently return 403. Existing kernel correlation remains PARTIAL; automatic NAT/clock-skew/volume mapping, live acquisition and signed binaries are not claimed. macOS/Linux packaging is outside this release scope.

The original no-context parser facades raise an explicit unconfigured-legacy error for backward compatibility. With ArtifactContext the MFT/USN/Prefetch/EVTX/PCAP facades perform real parsing. The generic UnsupportedParser remains an explicit unsupported contract and is never counted as PASS.

See [verification](VERIFICATION.md), [memory](VOLATILITY_ADAPTER.md), [disk](DISK_ADAPTER.md) and [network](NETWORK_ADAPTER.md) for exact evidence and limits.
