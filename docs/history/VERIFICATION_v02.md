> Historical v0.2 record. Current support and results are in ../VERIFICATION.md.

# v0.2 구현 검증 기록

검증일: 2026-09-16 UTC. Linux ARM64, Python 3.14.6, Node.js 24.19.0, Electron 44.4.1, TypeScript 7.0.2에서 직접 실행했습니다. Python 3.12, Windows/macOS, 원격 GitHub Actions 실행은 이번 세션에서 검증하지 않았습니다.

## 실행 결과

| 검증 | 실제 결과 |
|---|---|
| `pytest -q` | **102 passed**, 기존 63개 유지 + Volatility 39개 추가 |
| `ruff check .` / `ruff format --check .` | 통과, Python 57개 파일 format 일치 |
| JSON Schema export | Event / Correlation / Graph 재생성 |
| 실제 CLI Volatility import | 5개 파일, 14 rows → 8 Events, SQLite 저장과 출력 JSON 검증 |
| 원본 row / 파일 불변 | 고유 provenance 14개, JSON pointer 역참조 및 파일 SHA-256 동일 |
| Volatility graph | PARENT_OF 2, LOADED 3, CONNECTED_TO 1, correlation 20 |
| 기존 Sample 분석 | 입력 15, 관련 9, 직접 correlation 16, Noise 6 제외 유지 |
| `npm run typecheck` / `npm run build` | 통과 |
| Electron 개발 모드 E2E | 실제 API + SQLite + Electron 시나리오 통과 |
| `npm run package` | Linux ARM64 `desktop/release/EvidenceMesh-linux-arm64` 생성 |
| Electron 패키지 E2E | 생성한 실행 파일에서 같은 시나리오 통과 |
| Python wheel / sdist | `dist/evidence_mesh-0.2.0-py3-none-any.whl`, `.tar.gz` 생성 |
| 실제 화면 | 1440×900 캡처, 요구한 7개 view와 추가 provenance/DLL/entity graph 검토 |

pytest의 경고 2개는 기존 Starlette httpx TestClient와 AnyIO BlockingPortal alias deprecation입니다. 실패나 경고를 숨기지 않았습니다. fixture의 Volatility version은 제공된 메타데이터이며 실제 Volatility를 실행한 버전이라는 의미가 아닙니다.

## 직접 실행한 명령

저장소 루트의 `.venv`를 사용했습니다.

```bash
.venv/bin/python scripts/export_schemas.py
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python -m build
.venv/bin/python -m engine.cli import-memory tests/fixtures/volatility \
  --image-id final-fixture-memory --extracted-at 2026-09-16T09:35:00Z \
  --hostname workstation-01 --volatility-version 2.28.2 \
  --db data/volatility-final.sqlite3 --output data/volatility-final-events.json
```

마지막 import의 case ID는 `a48e4c99-a6fb-4c0c-a1f1-8e07c5db24d8`입니다. SQLite events count 8, 출력 JSON의 Pydantic 재검증, process_start 3 / socket 2 / module_load 3, 고유 원본 reference 14를 별도 Python assertion으로 확인했습니다. graph 결과는 `data/volatility-final-verification.json`에 있습니다. 2개 Event의 결측 시각은 extraction_time으로 표시되며 시간 점수가 없다는 경고가 출력됐습니다. 재실행에는 기존 output을 덮어쓰지 않도록 새 경로를 사용합니다.

Desktop:

```bash
cd desktop
npm run typecheck
npm run build
npm run package
xvfb-run -a -s '-screen 0 1600x1100x24' npm run test:e2e
EVIDENCEMESH_DESKTOP_EXECUTABLE="$PWD/release/EvidenceMesh-linux-arm64/EvidenceMesh" \
  xvfb-run -a -s '-screen 0 1600x1100x24' npm run test:e2e
```

## 추가 테스트 내용

`tests/test_volatility.py`의 39개 case는 5개 plugin 파싱, nested tree/PPID, cmdline 병합, source row 보존, 원본 불변, 중복 row/export, optional 결측, hex/IPv6/명시적 UTC 별칭, malformed JSON/중복 key/잘못된 tree, unknown plugin, 잘못된 숫자/시각, PID 재사용·이름/주소 충돌·이미지 범위, owner 귀속, 추출 시각의 잘못된 점수 방지, parent/DLL 그래프, Parser facade, cross-source sample 연결, SQLite round-trip, 실제 CLI 성공/실패 경로를 검증합니다.

기존 `test_schema.py`, `test_rules.py`, `test_sample.py`, `test_api_storage.py`, `test_cli.py`의 63개 테스트는 변경하지 않았습니다. schema validation을 우회하지 않고 모든 Event를 Normalizer/Pydantic으로 검증합니다.

## Electron E2E와 실제 렌더링

- 별도 port의 Uvicorn과 임시 SQLite, 실제 Electron main/preload/renderer를 실행합니다.
- Case/Evidence source 3개, 전체 sample Event 15개, Process 4개를 표시합니다.
- Enter로 PowerShell을 선택하고 실제 Analyze를 실행합니다. correlation row 16개, incident timeline 9개, Event graph node 9개와 edge 16개를 검증합니다.
- socket ↔ PCAP 연결의 score 90, same socket tuple, 0.2초 간격, 원본 출처를 Inspector에서 확인합니다.
- Timeline 전체/incident 전환, graph keyboard 선택·확장, 검색, no_matches, 빈 HTTP 화면, renderer 오류 부재, Node require 미노출을 확인합니다.
- 새 사건의 native 파일 선택 반환값만 자동 지정하여 실제 sample JSON 3개를 수입합니다. 파일 내용·IPC·API·DB·분석 결과는 mock하지 않습니다.
- 실제 CLI subprocess로 Volatility fixture 8개 Event를 수입하고 sample disk 6개 / network 4개를 추가합니다. Refresh로 사건을 열어 병합 process 3개, 원본 plugin 3개, DLL 3개, PARENT_OF 2개와 LOADED 3개를 검증합니다.
- 종료 시 app/backend와 임시 DB를 정리합니다.

캡처 목록과 링크는 [UI_DESIGN.md](UI_DESIGN.md)에 있습니다. `desktop/test-results/`와 `data/`는 생성 산출물로 Git에서 제외합니다. 최초 시각 검토에서 발견한 좁은 time delta 필드와 우측 graph label 잘림을 수정한 뒤 1440×900에서 다시 캡처했습니다.

## 구현 범위와 남은 한계

Volatility의 지정한 5개 JSON plugin 경로는 구현했습니다. 원시 메모리 해독/수집, Volatility runtime/symbol 관리, 다른 plugin과 JSONL/CSV/text renderer는 지원하지 않습니다. 테스트 fixture는 공식 renderer/plugin 형식을 모방한 **합성 데이터**이며 실제 메모리 이미지의 분석 결과로 성능을 검증한 것은 아닙니다.

MFT/USN/Prefetch/PCAP/EVTX 바이너리 parser는 여전히 명시적인 Stub입니다. HTTP/TLS 화면은 해당 Event가 없으면 빈 상태이며 네트워크 해독 기능을 주장하지 않습니다. Windows installer/서명, Python backend 동봉, 다중 호스트 정밀 identity, clock skew, 대규모 graph layout은 미구현입니다. Python/SQLite와 달리 브라우저 number는 53-bit 정밀도 제한이 있으므로 큰 원본 주소는 원본 JSON에서 확인해야 합니다.

## v0.1 기준선

같은 세션의 이전 검증에서 기존 63 tests, sample 15/9/16, live HTTP API, 독립 venv의 v0.1 wheel 실행, 개발/패키지 Electron E2E를 통과했습니다. 위 표는 현재 v0.2 재검증 결과입니다. 로컬 Git 저장소에는 원격 push를 수행하지 않았습니다.
