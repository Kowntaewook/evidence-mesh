# EvidenceMesh Workstation UI

제공된 `APEX-Windows-Source (1).zip`의 `frontend/src/App.tsx`, `ui.tsx`, `panels.tsx`, `styles.css`를 먼저 읽었습니다. 참고한 요소는 desktop shell, 좁은 icon rail, evidence navigation, dense table, 하단 inspector, 작은 control과 기술 값의 monospace 표기입니다. APEX의 React component를 복사하거나 런타임 의존성으로 추가하지 않았습니다. EvidenceMesh의 기존 Electron/TypeScript와 실제 API 모델을 유지하며 native DOM widget을 별도로 구현했습니다.

| 참고 구조 | EvidenceMesh 구현 |
|---|---|
| Topbar / rail / sidebar / inspector | 48px topbar, 68px rail, 238px evidence sidebar, 268px inspector |
| File 중심 table + detail | Process → related evidence → rule score/reasons → provenance |
| Cyan accent | Black/dark gray 배경, red 선택·primary·focus·높은 score |
| Sidebar navigation | Memory / Disk / Network evidence tree + Correlations / Timeline / Graph |
| Dense technical controls | 11px table, 34px row, 작은 radius, thin border, monospace PID/IP/path/hash/time |

1440×900 데스크톱을 우선으로 구성했습니다. 중앙 workspace는 여러 dashboard 카드 대신 테이블과 그래프를 사용합니다. Green은 Loaded, amber는 추출 시각 fallback 등의 상태에 제한합니다. 프로세스/파일/도메인/IP는 서로 다른 icon과 텍스트로 구분합니다. shell 내부 패널은 독립적으로 scroll됩니다.

## 실제 데이터 흐름

Case 생성 또는 Load Sample → Processes 선택 → Analyze Evidence → Correlations → Overview/Provenance/Raw Inspector → Timeline/Incident Graph 순서입니다. Import JSON은 기존 실제 IPC/API 입력을 사용합니다. Case 화면의 Import Memory / Import Disk / Import PCAP으로 원본 export/artifact를 직접 가져옵니다. 기존 CLI import 후 Refresh 경로도 유지합니다. DLL과 memory socket에는 동일 instance의 process 정보와 원본 plugin들이 표시됩니다.

테이블은 정렬과 현재 view 검색을 지원합니다. row에서 Enter/Space, 방향키, Home/End로 선택하며 focus-visible은 red outline입니다. graph node/edge도 keyboard focus와 Enter/Space를 지원합니다. Inspector는 rule별 점수와 time delta, 양쪽 실제 source reference를 표시하며 점수를 AI confidence나 확률로 표현하지 않습니다. 선택한 graph의 상세는 같은 Inspector로 이어집니다.

Graph는 Event 간 correlation과 Process/File/IP/Domain의 entity 관계를 전환합니다. entity 모드에는 실제 PARENT_OF/LOADED/CONNECTED_TO/RESOLVED가 나옵니다. Expand graph로 inspector 본문을 접어 넓게 볼 수 있습니다. 직접 edge의 점수만 표시하고 간접 경로를 직접 연결처럼 점수화하지 않습니다. 큰 graph의 정교한 auto layout, zoom/pan은 후속 작업입니다.

MFT/USN/Prefetch/EVTX/Amcache는 지원되는 원시 파일 또는 export에서 정규화한 관측을 보여 줍니다. HTTP/TLS는 해당 type의 관측이 있을 때만 표시하며 443 포트만으로 TLS 관측을 만들어 내지 않습니다. 빈 view와 no_matches, backend 오류를 명시적으로 표시합니다.

## 실제 Electron 캡처

개발 모드와 Linux ARM64 패키지에서 실제 Uvicorn + SQLite + Electron을 연결하여 1440×900으로 확인했습니다. 생성 파일은 `desktop/test-results/`에 있으며 Git에서는 제외합니다. 해당 폴더가 없는 checkout에서는 E2E 명령으로 다시 생성합니다.

| 화면 | 캡처 |
|---|---|
| Case / Evidence | [01-case-evidence.png](../desktop/test-results/01-case-evidence.png) |
| 전체 evidence table | [02-evidence-table.png](../desktop/test-results/02-evidence-table.png) |
| Process 목록 | [03-process-list.png](../desktop/test-results/03-process-list.png) |
| Process Detail | [04-process-detail.png](../desktop/test-results/04-process-detail.png) |
| Correlation 결과 | [05-correlations.png](../desktop/test-results/05-correlations.png) |
| Correlation Inspector | [06-correlation-inspector.png](../desktop/test-results/06-correlation-inspector.png) |
| Provenance | [07-provenance.png](../desktop/test-results/07-provenance.png) |
| Timeline | [08-timeline.png](../desktop/test-results/08-timeline.png) |
| Incident Graph | [09-incident-graph.png](../desktop/test-results/09-incident-graph.png) |
| 확장 Graph | [09b-incident-graph-expanded.png](../desktop/test-results/09b-incident-graph-expanded.png) |
| Volatility 병합 provenance | [10-volatility-provenance.png](../desktop/test-results/10-volatility-provenance.png) |
| DLL 목록 | [11-volatility-dlls.png](../desktop/test-results/11-volatility-dlls.png) |
| Process / DLL / parent 관계 | [12-process-dll-parent-graph.png](../desktop/test-results/12-process-dll-parent-graph.png) |

```bash
cd desktop
xvfb-run -a -s '-screen 0 1600x1100x24' npm run test:e2e
```

E2E는 native 파일 선택 결과만 자동 지정합니다. API 응답이나 화면 데이터는 mock하지 않으며, Volatility fixture import도 실제 CLI subprocess를 실행합니다. 샘플 15개 중 관련 9개 / 직접 링크 16개, keyboard 선택, no-match, JSON import, provenance, DLL, 부모/로드 관계, renderer 오류 부재를 검증합니다.

## v0.3 additions and verified scope

The original colors, rail/sidebar/table/inspector layout and baseline screenshots remain. New navigation includes Handles/Files, Memory Regions, Services, Modules/Drivers, Registry Artifacts, Event Logs, Amcache, Flows and Parser Runs.

Case imports require acquisition ID and aware extraction time; host, volume, timezone and recovered directory are optional. A recovered disk file can carry an explicit original logical path. No evidence facts are filled from the analyst machine. Parser Runs exposes SUCCESS/FAILED/UNAVAILABLE/SKIPPED, row/event counts, artifact, error, warnings, command and stderr.

Process Detail has Overview, Command Line, Parent/Children, DLLs, Handles, Files, Memory Regions, Sockets, Related Memory, Related Disk and Related Network. Each selected observation leads to its normal provenance/raw inspector. Correlation Inspector shows signed reasons, raw_score and clamped Correlation Score. Timestamp fallback remains labeled.

Tables render at most 100 rows per page. API loading is chunked at 2,000 Events, while the renderer still retains the full case. Graph display is capped at 200 nodes/400 edges with a notice. Repeated entity edges coalesce with support counts; full path tooltips accompany compact file labels. Dense graph layout and 100k-event UI responsiveness are not claimed as validated. Timeline filters source and process/file/registry/DNS/connection/service categories.

New 64-bit addresses display as hexadecimal strings. Unsafe numeric values from API JSON retain exact decimal strings in Raw rather than rounded JavaScript numbers.

| v0.3 screen | Actual packaged Electron capture |
|---|---|
| Artifact imports | [14-cross-source-imports.png](../desktop/test-results/14-cross-source-imports.png) |
| Parser runs | [15-parser-runs.png](../desktop/test-results/15-parser-runs.png) |
| Cross-source correlations | [16-cross-source-correlations.png](../desktop/test-results/16-cross-source-correlations.png) |
| Process / disk details | [17-process-disk.png](../desktop/test-results/17-process-disk.png) |
| Process / network details | [17-process-network.png](../desktop/test-results/17-process-network.png) |
| Frame provenance | [18-cross-source-provenance.png](../desktop/test-results/18-cross-source-provenance.png) |
| Filtered timeline | [19-cross-source-timeline.png](../desktop/test-results/19-cross-source-timeline.png) |
| Typed entity graph | [20-cross-source-entity-graph.png](../desktop/test-results/20-cross-source-entity-graph.png) |
| Exact 64-bit handle | [21-handles-64bit-address.png](../desktop/test-results/21-handles-64bit-address.png) |
| Invalid capture failure | [24-parser-failure.png](../desktop/test-results/24-parser-failure.png) |

Development and packaged Linux ARM64 E2E both passed. Each creates a real case, imports Memory + five Disk formats + content file + PCAPNG (67 Events), confirms 28 successful runs, analyzes PID 4120 (34 related), opens all three related-source tabs, reasons/frame provenance, filters the timeline, selects typed graph relationships and tests a failed capture import. Only native file-picker results are supplied by the test; API, SQLite and tshark remain real. Original 15/9/16 sample assertions are still included.
