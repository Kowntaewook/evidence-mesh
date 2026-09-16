# EvidenceMesh

**Cross-source forensic correlation engine for memory, disk, and network evidence.**

Memory ↔ Disk ↔ Network 증거를 공통 Event로 정규화하고, 선택한 프로세스와 관련된 파일·DNS·연결을 근거와 함께 연결하는 포렌식 분석 엔진입니다. 저장소 이름은 `evidence-mesh`, 라이선스는 MIT입니다.

메모리에서 찾은 프로세스, 디스크의 파일 흔적, PCAP의 연결은 서로 다른 형식과 시간 기준을 사용합니다. EvidenceMesh는 도구별 결과를 직접 비교하지 않고 공통 스키마를 거쳐 사건 그래프와 타임라인을 만듭니다. 점수와 그 산출 근거를 함께 저장하므로 분석자가 연결을 검토할 수 있습니다. 점수는 확률이나 악성 판정이 아닙니다.

## v0.3 기능

- Pydantic Event Schema, UTC 정규화, Windows 경로 비교, 원본 reference 보존
- 후보 인덱스를 이용하는 Temporal / Process / File / Network / Artifact 규칙, 양수·음수 근거와 raw score
- 점수·rule version·필드 근거·설명을 보존하는 SQLite 저장소
- 프로세스 중심 연결 컴포넌트, Incident Graph, 시간순 Timeline
- FastAPI 사건 생성·JSON 입력·분석·조회 API와 OpenAPI
- Volatility JSON 21종: 기존 5개 병합을 유지하면서 scan, handles, VAD, services, registry, kernel, dumpfiles 추가
- MFT/USN v2/SCCA Prefetch/EVTX/Amcache 원시 파일과 문서화된 CSV·JSON export 입력
- 실제 PCAP/PCAPNG를 offline tshark로 해독: DNS, TCP/UDP flow, HTTP, TLS SNI
- Electron / TypeScript Black + Red workstation: Evidence tree → Process → Correlation → Inspector / Provenance → Timeline / Graph
- 기존 Sample 15개 / 관련 9개 / 링크 16개 유지; 새 사건 67개 / 관련 34개 / 명시적 Noise 29개
- 원본 hash/size/path/imported_at, parser run 상태·오류, case manifest, SQLite migration, 100행 UI pagination

**작동 범위:** 메모리는 외부에서 생성한 Volatility JSON을 사용합니다. 원시 메모리 이미지 분석/덤프 실행은 자동화하지 않습니다. 압축 MAM Prefetch와 USN v3/v4는 `UNAVAILABLE`이며 export로 입력할 수 있습니다. 원시 MFT/USN/SCCA는 합성 바이너리로 검증했고 실제 이미지에서는 검증하지 못했습니다. 공개 EVTX/Amcache와 기존 PCAP은 별도로 읽었습니다. 정확한 범위는 [지원표](docs/PARSER_SUPPORT.md), 결과는 [검증 기록](docs/VERIFICATION.md)에 있습니다.

## Architecture

```text
Read-only Evidence → Collector / Parser → Normalizer → Unified Event
                                                        ↓
                                                 SQLite Repository
                                                        ↓
                                             Deterministic Rule Engine
                                                        ↓
                                       Correlations + Reasons → Incident Graph
                                                        ↓
                                            Timeline / API / Desktop UI
```

```text
engine/collectors/{memory,disk,network}   기존 artifact 읽기
engine/parsers/                          JSON / Volatility reader + 설정 가능한 Parser facade
engine/ingestion/                        사건 입력, 공통 원본 읽기, 실행 결과 기록
engine/normalization/                    Event 검증, UTC / IP / host 정규화
engine/correlation/                      독립 규칙 및 deterministic scoring
engine/graph/                            Node / Edge projection
engine/storage/                          Repository protocol + SQLite
api/                                    FastAPI app factory
desktop/                                Electron main / preload / renderer
schemas/                                Pydantic 모델과 생성된 JSON Schema
samples/sample_case/                    memory / disk / network JSON
samples/cross_source/                   21개 memory export + disk artifact + 실제 capture container
tests/                                  pytest 검증
docs/                                   설계, 스키마, 규칙, 검증 기록
```

Python 3.12+, Pydantic 2, SQLite, FastAPI, Uvicorn, Electron, TypeScript를 사용합니다. Python 분석은 AI나 외부 모델에 의존하지 않습니다. 패키지 관리 파일은 `pyproject.toml`, `requirements.lock`, `desktop/package-lock.json`입니다.

## 설치

Python 3.12 이상과 Node.js 22.12 이상이 필요합니다. 개발/검증 환경은 Python 3.14 및 Node 24입니다. Linux Electron에는 GTK/NSS 등 Chromium 런타임 라이브러리가 필요합니다. Windows에서는 일반 사용자 계정으로 실행합니다.

```bash
cd evidence-mesh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install -e '.[dev]'
# Debian/Ubuntu: PCAP 입력을 위한 외부 decoder
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
cd desktop
npm ci
cd ..
```

Windows PowerShell:

```powershell
cd evidence-mesh
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.lock
python -m pip install -e ".[dev]"
cd desktop
npm ci
cd ..
```

## 실행

첫 번째 터미널에서 저장소 루트의 가상환경을 활성화한 후 API를 실행합니다.

```bash
python -m uvicorn api.main:app --host 127.0.0.1 --port 8765
```

두 번째 터미널:

```bash
cd evidence-mesh/desktop
npm start
```

API 주소는 `http://127.0.0.1:8765`, Swagger 문서는 `/docs`, 스키마는 `/openapi.json`입니다. Desktop은 API를 자동 실행하지 않으므로 API 터미널을 열어 둡니다. API는 로컬 단일 사용자용이며 인증을 제공하지 않습니다.

설정:

| 환경 변수 | 기본값 | 용도 |
|---|---|---|
| `EVIDENCEMESH_DB` | `data/evidencemesh.sqlite3` | 분석 DB 위치; 원본 증거와 다른 위치 사용 |
| `EVIDENCEMESH_SAMPLE_DIR` | 저장소의 `samples/sample_case` | API 샘플 폴더 |
| `EVIDENCEMESH_API` | `http://127.0.0.1:8765` | Desktop의 로컬 API origin |
| `EVIDENCEMESH_PYTHON` | `.venv`의 Python | Desktop E2E 검증용 Python 경로 |

## Sample 분석

1. Desktop에서 **Load Sample Evidence**를 클릭합니다. 매번 별도 사건이 생성됩니다.
2. **Processes**에서 **powershell.exe · PID 4120 · 09:31:25**를 선택합니다. 같은 PID를 재사용한 Noise process도 별도로 표시됩니다.
3. **Analyze Evidence**를 클릭합니다.
4. 관련 이벤트 9개, 근거를 가진 링크 16개, 시간순 타임라인이 표시됩니다.
5. 링크 또는 그래프 선을 클릭해 score, rule, 설명, source artifact, parser, raw reference를 확인합니다.
6. `notepad.exe`를 선택해 분석하면 `No matching evidence`가 표시됩니다.

시나리오는 `explorer.exe → invoice.zip → powershell.exe → a.ps1 → evil.example → 185.10.10.5:443`입니다. ZIP과 실행의 인과관계를 자동으로 확정하지 않습니다. ZIP을 기록한 explorer 프로세스, PowerShell의 PPID, 스크립트 경로, 소켓 tuple과 DNS 응답으로 사건의 관측 정보를 연결합니다. IP/도메인은 문자열 데이터이며 접속하거나 실행하지 않습니다. 악성코드·스크립트 payload·원본 대용량 이미지는 포함하지 않습니다.

CLI에서도 같은 분석을 실행할 수 있습니다.

```bash
python -m engine.cli sample --db data/demo.sqlite3 --output data/demo-report.json
```

출력 JSON에는 case, correlations/reasons, graph, timeline이 모두 들어갑니다. 기존 report 경로에는 덮어쓰지 않으므로 재실행 시 새 출력 이름을 사용합니다. `--samples`, `--root`로 입력 폴더와 선택 이벤트를 변경할 수 있습니다. CLI의 기본 root는 `MEM-PS`입니다.

주요 실제 점수:

| 연결 | 점수 | 주요 근거 |
|---|---:|---|
| PowerShell → MFT의 a.ps1 | 85 | command line 경로 50 + 시간 30 + NTFS 5 |
| Memory socket → PCAP connection | 90 | 5-tuple 60 + 시간 30 |
| DNS → PCAP connection | 80 | resolved IP 40 + DNS 선행 10 + 시간 30 |

이는 직접 edge 점수입니다. PowerShell → socket → DNS처럼 여러 단계를 통과하는 연결에 점수를 곱하거나 직접 연결로 표시하지 않습니다.

## Volatility JSON import

Volatility의 JSON renderer가 만든 `pslist.json`, `pstree.json`, `cmdline.json`, `netscan.json`, `dlllist.json`을 같은 폴더에 둡니다. 하나의 메모리 이미지에서 추출한 결과만 한 번에 병합합니다. `--image-id`는 실제 증거 식별자, `--extracted-at`은 분석 결과를 추출한 timezone 포함 시각입니다.

다음 명령은 저장소의 **합성 Volatility 형식 fixture**를 실제로 변환하고 SQLite에 저장합니다.

```bash
python -m engine.cli import-memory tests/fixtures/volatility \
  --image-id fixture-memory-01 --extracted-at 2026-09-16T09:35:00Z \
  --hostname workstation-01 --volatility-version 2.28.0 \
  --db data/evidencemesh.sqlite3 --output data/volatility-events.json
```

5개 파일의 14개 row가 8개 Event로 정규화됩니다: process 3, socket 2, DLL 3. 같은 DB를 사용하는 Desktop에서 **Refresh** 후 생성된 사건을 선택합니다. 또는 새 사건에 출력 JSON을 Import JSON으로 수입합니다. CLI는 수입만 수행하며 **Processes → Analyze Evidence**에서 분석합니다. 출력 파일은 덮어쓰지 않습니다.

단일 파일은 `import-memory pslist.json --plugin windows.pslist ...`로 지정합니다. 알려지지 않은 Volatility 버전은 생략할 수 있으며 `null`과 경고로 기록합니다. 결측 사건 시각은 명시적인 `extraction_time`으로 표시하고 시간 기반 점수를 부여하지 않습니다. 입력 형식·내부 API·병합 정책은 [Volatility Adapter](docs/VOLATILITY_ADAPTER.md), UI 구조는 [UI Design](docs/UI_DESIGN.md)을 참고합니다.

## API

| Method | Path | 동작 |
|---|---|---|
| GET | `/health` | 서버와 DB 연결 확인 |
| POST / GET | `/cases` | 사건 생성 / 목록 |
| GET | `/cases/{case_id}` | 사건과 revision 조회 |
| POST / GET | `/cases/{case_id}/events` | Event 배열 입력 / 조회 (`source`, `pid` 필터) |
| POST | `/cases/{case_id}/correlate` | 전체 사건 분석, optional `root_event_id`, `min_score` |
| GET | `/cases/{case_id}/correlations` | 보존된 근거 포함 연결 |
| GET | `/cases/{case_id}/graph` | 그래프 |
| GET | `/cases/{case_id}/timeline` | UTC 타임라인 |
| POST | `/cases/{case_id}/import/{memory,disk,network}` | 원본 경로 + acquisition context 입력, parser run 결과 반환 |
| GET | `/cases/{case_id}/{processes,files,network}` | 해당 하위 모델이 있는 관측, limit/offset 지원 |
| GET | `/cases/{case_id}/{imports,parser-runs}` | 성공·실패·미지원·미입력 기록 |
| GET | `/parsers/volatility` | 설치된 plugin/alias discovery |
| POST | `/samples/load` | 합성 사건 만들기 |

correlations/graph/timeline 조회에 `?root_event_id=MEM-PS`를 지정하면 선택 프로세스의 연결 컴포넌트를 조회합니다. 분석 전에 graph/correlations를 조회하면 409, 없는 사건·root는 404, 잘못된 request schema는 422입니다. 기존 `/events`의 중복 ID는 409이며 batch가 rollback됩니다. 새 artifact import는 parser/storage 실패를 `ImportReport.status`와 `runs[].error`에 기록합니다. HTTP 200만으로 성공을 판단하지 않습니다. 입력 추가 후 기존 분석은 무효화됩니다. `/events`는 source/pid/event_type/artifact_type/limit/offset, Timeline은 source/category/pid/start/end/limit/offset 필터를 지원합니다. JSON batch당 5,000개 제한은 유지하지만 사건 분석의 5,000개 제한은 제거했습니다.

## Cross-source 사건 입력

```bash
python -m engine.cli import-case samples/cross_source --db data/cross-source.sqlite3
# 출력의 case_id 사용
python -m engine.cli correlate --db data/cross-source.sqlite3 --case-id CASE_ID
python -m engine.cli timeline --db data/cross-source.sqlite3 --case-id CASE_ID
python -m engine.cli graph --db data/cross-source.sqlite3 --case-id CASE_ID
python -m engine.cli parser-runs --db data/cross-source.sqlite3 --case-id CASE_ID
python -m engine.cli discover-plugins
```

개별 입력은 `case-create --name NAME` 후 `import memory|mft|usn|prefetch|evtx|amcache|file|pcap INPUT --case-id ID --acquisition-id ID --extracted-at ISO_TIME`입니다. 모든 명령에 `--db`를 지정할 수 있습니다. `--hostname`, `--volume-id`, `--timezone`, `--mount-point`, `--logical-path`, `--recovered-directory`는 알고 있는 경우에만 지정합니다. [Case format](docs/CASE_FORMAT.md)에 완전한 manifest 예시가 있습니다.

Desktop의 Case 화면에서도 **Import Memory / Import Disk / Import PCAP**으로 직접 입력합니다. Memory는 같은 이미지의 export 폴더를 선택합니다. PID 4120 선택 후 Analyze하면 `a.ps1` command line·handle·MFT·USN·Prefetch, `example.test` DNS/TLS, `203.0.113.20:443` 메모리 socket/PCAP flow를 추적할 수 있습니다. 출력 및 DB는 입력 evidence 폴더 밖에 둡니다.

## 검증 및 패키징

```bash
pytest -q
ruff check .
ruff format --check .
python -m build
cd desktop
npm run typecheck
npm run build
npm run package
npm run test:e2e
```

`npm run package`는 현재 OS/CPU용 실행 디렉터리를 `desktop/release/`에 만듭니다. Python API는 별도로 실행해야 합니다. Windows installer, macOS 서명/공증, Python runtime 동봉은 아직 없습니다. Linux headless 검증은 `xvfb-run -a npm run test:e2e`를 사용하며 Xvfb와 xauth가 필요합니다. 테스트는 임시 DB와 실제 Uvicorn/Electron 프로세스를 사용하고 종료 시 정리합니다. 루트 컨테이너에서만 E2E runner가 `--no-sandbox`를 추가하며 일반 `npm start`에는 적용하지 않습니다.

자세한 실제 검증 결과는 [docs/VERIFICATION.md](docs/VERIFICATION.md)에 기록합니다. GitHub Actions workflow는 Python 3.12/3.14 검증과 Linux Desktop 빌드를 정의합니다. 로컬 실행 결과와 원격 CI 실행은 별개입니다.

## 검증 범위와 한계

10,000 / 50,000 / 100,000 synthetic normalized events로 import·correlation·peak memory·DB 크기를 측정했습니다. 최종 100,000개 실행은 import 14.52초, correlation 11.80초, peak 1,425.45 MiB입니다. 49억 9,995만 전체 쌍 중 21만 후보만 평가했습니다. 원시 이미지 decoding 또는 전체 graph rendering 성능 수치는 아닙니다. 같은 identity가 매우 밀집한 그룹은 여전히 많은 실제 연결을 만들 수 있습니다.

실제 메모리 이미지: **NOT VALIDATED WITH REAL IMAGE**. MAM 압축, USN v3/v4, 삭제 registry cell 복원, transaction log replay, TLS 복호화, NAT/clock-skew 자동 보정, device-volume alias 자동 추정은 지원하지 않습니다. Windows/macOS 패키지와 설치·서명, Python backend 동봉도 검증하지 않았습니다. 높은 Correlation Score는 사건의 인과관계나 악성을 확정하지 않습니다. psscan/malfind/module mismatch는 관측 신호로만 표시합니다. AI API는 사용하지 않습니다.

설계 상세: [Architecture](docs/ARCHITECTURE.md), [Event Schema](docs/EVENT_SCHEMA.md), [Correlation Rules](docs/CORRELATION_RULES.md).
