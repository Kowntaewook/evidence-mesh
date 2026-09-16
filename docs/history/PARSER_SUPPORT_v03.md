# Parser support matrix — v0.3

PASS means implemented and tested **within the input scope stated here**. It does not mean every OS/tool version or real-image scenario was validated. PARTIAL means the described subset is implemented. UNAVAILABLE means the runtime format/dependency cannot be used. TODO means no implementation is offered.

Runtime ParserRun statuses are separate: SUCCESS, FAILED, UNAVAILABLE, SKIPPED. A successful import with sparse fields is not a claim of complete forensic interpretation.

## Memory: existing Volatility JSON exports

All rows: Parse/Normalize/Provenance/Test PASS for documented synthetic export fixtures. Installed Volatility 2.28.0 discovery found all 21. Raw image plugin execution remains **NOT VALIDATED WITH REAL IMAGE**.

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
| dumpfiles | PASS | PASS | PASS | PASS | PASS | 기존 recovered bytes 검증·SHA-256; 추출 실행은 외부 |

## Disk

| Input | Parse | Normalize | Provenance | Correlation | Test | Notes |
|---|---|---|---|---|---|---|
| MFT JSON/CSV | PASS | PASS | PASS | PASS | PASS | Tested aliases / record+sequence+volume |
| Raw MFT | PASS | PASS | PASS | PASS | PASS | Synthetic FILE records; real image NOT VALIDATED |
| USN JSON/CSV | PASS | PASS | PASS | PASS | PASS | Reason/reference preservation |
| Raw USN v2 | PASS | PASS | PASS | PASS | PASS | Synthetic binary; MFT enrichment |
| Raw USN v3/v4 | UNAVAILABLE | UNAVAILABLE | PARTIAL | UNAVAILABLE | PASS | Explicit unsupported status; input integrity retained |
| Prefetch JSON/CSV | PASS | PASS | PASS | PASS | PASS | Executable, run times and references |
| Raw SCCA Prefetch | PARTIAL | PASS | PASS | PASS | PARTIAL | Implemented layouts 17/23/26/30/31; tested raw v30 synthetic |
| Raw MAM Prefetch | UNAVAILABLE | UNAVAILABLE | PARTIAL | UNAVAILABLE | PASS | Public compressed file rejected honestly; use export |
| EVTX raw/XML/exports | PASS | PASS | PASS | PASS | PASS | Public raw files 759/5 Events; specialized provider subset |
| Amcache raw/exports | PASS | PASS | PASS | PASS | PASS | Public modern/legacy hives 222/69 Events |
| Content file | PASS | PASS | PASS | PASS | PASS | Actual SHA-256; explicit original logical path |
| Whole disk image / deleted-cell recovery | TODO | TODO | TODO | TODO | TODO | Extract artifacts externally |

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
| TLS | PASS | PASS | PASS | PASS | PASS | Observed ClientHello/SNI/version; no decryption |
| Missing tshark | UNAVAILABLE | UNAVAILABLE | PARTIAL | UNAVAILABLE | PASS | Explicit status; never empty success |
| TLS decrypt / HTTP-body file recovery | TODO | TODO | TODO | TODO | TODO | No download-causation inference |

## System boundaries

Indexed default correlation, negative reasons/lifetime gates, additive SQLite migration, CLI/local API, native Desktop imports, process details, parser audit, typed graph and filtered timeline are implemented and exercised.

UI large-case support is PARTIAL: paginated DOM and graph caps are implemented; renderer still holds the full loaded case, and 100k-event interactive performance was not measured. Raw memory automation, whole-image acquisition, automatic NAT/clock-skew/volume mapping and signed Windows/macOS installers are TODO.

The original no-context parser facades raise an explicit unconfigured-legacy error for backward compatibility. With ArtifactContext the MFT/USN/Prefetch/EVTX/PCAP facades perform real parsing. The generic UnsupportedParser remains an explicit unsupported contract and is never counted as PASS.

See [verification](VERIFICATION.md), [memory](VOLATILITY_ADAPTER.md), [disk](DISK_ADAPTER.md) and [network](NETWORK_ADAPTER.md) for exact evidence and limits.
