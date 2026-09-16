# EvidenceMesh v0.3 최종 보고서

## 1. Baseline

기존 102개 테스트 파일과 5개 Volatility adapter의 동작을 유지했습니다. 신규 140개 테스트, 총 21종 memory export, 5종 disk artifact, 실제 PCAP/PCAPNG, 인덱스 기반 correlation, SQLite migration, CLI/API/UI 입력과 감사 기록을 추가했습니다. 기존 Black/Red UI를 확장했습니다.

## 2. Memory Support

PASS는 문서화된 JSON export와 테스트 범위를 뜻합니다. 원시 이미지 실행 검증과는 구분합니다.

| Plugin (windows.) | Parse | Normalize | Correlation | Test | Notes |
|---|---|---|---|---|---|
| pslist | PASS | PASS | PASS | PASS | 기존 병합 |
| pstree | PASS | PASS | PASS | PASS | 부모/자식 identity |
| cmdline | PASS | PASS | PASS | PASS | 경로 참조 |
| netscan | PASS | PASS | PASS | PASS | socket/PCAP tuple |
| dlllist | PASS | PASS | PASS | PASS | DLL/process/file |
| psscan | PASS | PASS | PASS | PASS | 별도 관측; pslist 비교 |
| envars | PASS | PASS | PASS | PASS | process 환경 변수 |
| handles | PASS | PASS | PASS | PASS | raw type, FILE_OBJECT |
| filescan | PASS | PASS | PASS | PASS | file object/path |
| vadinfo | PASS | PASS | PASS | PASS | region/process |
| malware.malfind | PASS | PASS | PASS | PASS | suspicious region; 악성 판정 없음 |
| svcscan | PASS | PASS | PASS | PASS | service/binary/process |
| svclist | PASS | PASS | PASS | PASS | 설치된 2.28.0에서 available |
| registry.amcache | PASS | PASS | PASS | PASS | Memory/Disk source 분리 |
| registry.userassist | PASS | PASS | PASS | PASS | registry/file/process |
| shimcachemem | PASS | PASS | PASS | PASS | cached file 관측 |
| modules | PASS | PASS | PARTIAL | PASS | path 연결·scan 비교; 전용 kernel score 없음 |
| modscan | PASS | PASS | PARTIAL | PASS | modules 비교 signal |
| driverscan | PASS | PASS | PARTIAL | PASS | graph 관측; 전용 scored 관계 없음 |
| callbacks | PASS | PASS | PARTIAL | PASS | callback 관측; 전용 scored 관계 없음 |
| dumpfiles | PASS | PASS | PASS | PASS | 기존 recovered bytes SHA-256; 추출 실행은 외부 |

설치된 Volatility 2.28.0에서 21종 discovery를 확인했습니다. 실제 renderer를 사용한 형식 호환성은 검증했지만 **NOT VALIDATED WITH REAL IMAGE**입니다.

## 3. Disk Support

| Artifact | Parse | Normalize | Correlation | Test | Notes |
|---|---|---|---|---|---|
| MFT | PASS | PASS | PASS | PASS | raw/JSON/CSV; raw는 합성 FILE record 검증 |
| USN | PASS | PASS | PASS | PASS | raw v2/exports; v3/v4 UNAVAILABLE |
| Prefetch | PARTIAL | PASS | PASS | PASS | export와 SCCA v30 fixture; MAM UNAVAILABLE |
| EVTX | PASS | PASS | PASS | PASS | raw/XML/exports; 공개 raw 759/5 Events |
| Amcache | PASS | PASS | PASS | PASS | modern/legacy raw; 공개 hive 222/69 Events |
| Content file | PASS | PASS | PASS | PASS | 실제 파일 SHA-256/size; 원래 경로 명시 |

원시 SCCA 17/23/26/30/31 layout을 구현했지만 v30 외 실제 형식 coverage는 제한적입니다. whole disk image 검증은 하지 못했습니다. 세부 범위는 [지원표](PARSER_SUPPORT.md)에 기록했습니다.

## 4. Network Support

| Protocol / input | Parse | Normalize | Correlation | Test | Notes |
|---|---|---|---|---|---|
| PCAP / PCAPNG | PASS | PASS | PASS | PASS | 실제 tshark 4.6.6 decoding |
| DNS | PASS | PASS | PASS | PASS | query/response, A/AAAA, client context |
| TCP | PASS | PASS | PASS | PASS | 양방향 flow/interval/flags/counts |
| UDP | PASS | PASS | PASS | PASS | tuple/stream |
| HTTP | PASS | PASS | PASS | PASS | 보이는 request/response metadata |
| TLS | PASS | PASS | PASS | PASS | ClientHello/SNI/version; 복호화 없음 |

## 5. Cross-Source Correlation

67개 Event 중 PID 4120 관련 **34개**, 관련 correlation **259개**를 확인했습니다. 명시적 Noise **29개**와 추가 kernel 관측 4개는 관련 컴포넌트 밖에 남았습니다.

```text
Memory powershell.exe PID 4120
  ├ command line / handle / FILE_OBJECT → a.ps1
  ├ recovered bytes SHA-256 ↔ Disk content
  ├ path / MFT record+sequence ↔ MFT / USN / Prefetch / Amcache
  └ socket 5-tuple ↔ PCAP flow → DNS example.test / TLS SNI
                                       → 203.0.113.20:443
```

양수·음수 reason, raw_score, PID 재사용/lifetime/host/client 충돌 방지, timestamp precision, provenance를 보존합니다. 점수는 확률·악성 판정이 아닙니다.

## 6. UI

기존 색상·레이아웃을 유지하면서 Memory/Disk/PCAP 직접 입력, 새 evidence tree, 11개 process detail 탭, Parser Runs/오류 inspector, source/category timeline 필터, typed entity graph를 추가했습니다. 표는 100행 단위이며 64-bit 주소를 정확하게 표시합니다. Graph 표시 상한과 전체 case를 renderer 메모리에 보유하는 한계는 명시했습니다.

## 7. Tests

```text
Total:   242
Passed:  242
Failed:    0
Skipped:   0
```

기존 102개 + 신규 140개입니다. dependency deprecation warning 2개가 있습니다. 다른 환경에서 optional dependency/public fixture가 없으면 해당 compatibility test가 skip될 수 있습니다.

## 8. Performance

| Dataset size | Import time | Correlation time | Peak memory | SQLite | Correlations |
|---:|---:|---:|---:|---:|---:|
| 10,000 | 1.605s | 0.986s | 177.50 MiB | 62,017,536 bytes | 20,000 |
| 50,000 | 7.585s | 5.903s | 733.89 MiB | 310,099,968 bytes | 100,000 |
| 100,000 | 14.522s | 11.804s | 1,425.45 MiB | 620,584,960 bytes | 200,000 |

100k에서 전체 4,999,950,000쌍 대신 210,000 후보를 평가했습니다. correlation 저장은 별도로 28.229초였습니다. 합성 normalized Event 측정이며 raw decoding/graph/UI benchmark는 아닙니다. 같은 identity가 밀집하면 실제 edge 수는 여전히 커질 수 있습니다.

## 9. Commands

실행한 전체 최종 검증 명령과 13개 CLI command 원문은 [VERIFICATION.md](VERIFICATION.md#commands-actually-executed)에 기록했습니다. 핵심 실행은 editable dev install, pytest, ruff lint/format, schema export, Python build, plugin discovery, 10k/50k/100k benchmark, 실제 Uvicorn과 24개 HTTP call, npm typecheck/build/package 및 개발·패키지 E2E입니다.

독립 virtualenv에 wheel을 설치하고 checkout 밖에서 sample/import-case/correlate/timeline/graph/parser-runs를 실행했습니다. 패키지 버전 0.3.0과 site-packages에서의 import, 포함된 fixture 67개 입력을 확인했습니다. 정확한 command/case/path는 `data/wheel-v03-report.json`, CLI는 `data/cli-verification-v03/commands.json`, HTTP는 `data/live-api-v03-report.json`에 있습니다.

## 10. E2E

개발 모드와 **패키지 Electron 모두 PASS**입니다. 실제 API/SQLite/tshark로 사건 생성 → Memory/5종 Disk/content/PCAPNG 입력 → 28개 성공 run → process 선택 → 관련 Memory/Disk/Network → 이유/provenance → timeline/graph → invalid PCAP 오류 표시까지 확인했습니다.

원본 Sample 15/9/16 assertion과 keyboard/no-match/provenance 흐름도 유지했습니다. 캡처 28개가 `desktop/test-results/`에 있으며, [graph](../desktop/test-results/20-cross-source-entity-graph.png), [process details](../desktop/test-results/17-process-disk.png), [parser failure](../desktop/test-results/24-parser-failure.png)를 직접 확인했습니다.

## 11. Real-data Validation

**PARTIALLY VALIDATED**

공개 Amcache hive 2개와 EVTX 2개, 환경에 있던 PCAP 2개를 실제로 읽었습니다. PCAP 결과는 20,000 packets → 39,929 Events와 2,826 packets → 7 flows입니다. 공개 compressed Prefetch는 UNAVAILABLE을 기록했습니다.

Volatility는 실제 JsonRenderer 형식만 검증했습니다. 원시 메모리/디스크 이미지: **NOT VALIDATED WITH REAL IMAGE**. 공개 테스트 파일과 출처 이력이 알려지지 않은 PCAP을 실제 사건 정답 데이터로 주장하지 않습니다.

## 12. Unsupported

MAM Prefetch, USN v3/v4, raw memory 자동 분석/추출, whole disk mounting, registry 삭제 cell/transaction-log 복원, TLS 복호화, HTTP body 파일 복원, NAT/clock-skew/device-volume 자동 보정은 미지원입니다. kernel driver/callback 전용 점수 관계는 PARTIAL입니다.

100k UI 성능, Windows/macOS package·서명·installer, Python backend 동봉, 원격 CI는 검증하지 않았습니다. Linux ARM64 실행 패키지는 별도 Python API와 외부 도구가 필요합니다.

## 13. Regression

기존 테스트 파일 byte hash를 유지했고 **102개 모두 통과**했습니다. 기존 5개 plugin fixture **14 rows → 8 Events**, Sample **15 Events / 9 related / 16 links**, Black/Red Electron 분석 흐름이 개발·패키지 E2E에서 유지됐습니다.
