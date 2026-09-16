# EvidenceMesh

[![Download for Windows](https://img.shields.io/badge/Download-Windows-red)](https://github.com/Kowntaewook/evidence-mesh/releases/latest)
[![Latest Release](https://img.shields.io/github/v/release/Kowntaewook/evidence-mesh)](https://github.com/Kowntaewook/evidence-mesh/releases/latest)

**v0.4.0 is now available.**  
The Windows x64 installer, corresponding-source archive, Windows E2E verification report, and SHA-256 manifest are published on the latest release page.

**Cross-source forensic correlation engine for memory, disk, and network evidence.**

EvidenceMesh normalizes **Memory ↔ Disk ↔ Network** evidence into a unified Event model and correlates files, DNS observations, and network connections related to a selected process, together with the evidence used to justify each link.

The project source is licensed under MIT. Bundled third-party components remain subject to [their respective licenses](docs/THIRD_PARTY_LICENSES.md).

Processes found in memory, file artifacts recovered from disk, and connections observed in PCAPs all use different formats and time references. EvidenceMesh does not directly compare tool-specific outputs. Instead, it maps them into a common schema and builds an incident graph and timeline.

Correlation scores are stored together with the rules and evidence that produced them so analysts can review every link.

> A correlation score is not a probability and is not a malware verdict.

## Features

- Pydantic Event schema
- UTC timestamp normalization
- Windows path normalization and comparison
- Preservation of original evidence references
- Temporal / Process / File / Network / Artifact correlation rules
- Positive and negative evidence with deterministic raw scoring
- Candidate indexing to avoid unnecessary all-to-all comparisons
- SQLite repository with preserved:
  - scores
  - rule versions
  - field-level evidence
  - explanations
- Process-centered connected components
- Incident Graph
- Chronological Timeline
- FastAPI APIs for:
  - case creation
  - evidence ingestion
  - analysis
  - querying
  - OpenAPI
- Support for 21 Volatility JSON plugin types
- MFT / USN / Prefetch / EVTX / Amcache parsing
- Offline PCAP / PCAPNG analysis using TShark
- DNS, TCP/UDP flow, HTTP, and TLS metadata extraction
- Electron + TypeScript forensic workstation
- Parser-run status and error tracking
- Original artifact hash / size / path / import time preservation
- Case manifests and SQLite migrations
- Server-side pagination for large cases
- Bounded graph queries

### Added in v0.4

- Bundled TShark
- Bundled Python / Volatility runtime
- Automatic loopback backend startup and shutdown
- Raw-memory plugin orchestration
- Progress tracking
- Cancellation
- Result caching
- MAM4 Prefetch decompression
- USN v3 / v4 support
- Read-only NTFS image discovery and extraction
- HTTP body recovery and SHA-256 hashing
- TLS decryption with a supplied session key log
- Large-case server-side paging
- Bounded graph queries
- Self-contained Windows installer
- Installed-application E2E validation

**Raw-memory execution is implemented but has NOT BEEN VALIDATED WITH A REAL MEMORY IMAGE.**

See:

- [Parser Support Matrix](docs/PARSER_SUPPORT.md)
- [Verification Record](docs/VERIFICATION.md)
- [Windows Packaging](docs/WINDOWS_PACKAGING.md)

---

## Architecture

```text
Read-only Evidence
        ↓
Collector / Parser
        ↓
Normalizer
        ↓
Unified Event
        ↓
SQLite Repository
        ↓
Deterministic Rule Engine
        ↓
Correlations + Reasons
        ↓
Incident Graph
        ↓
Timeline / API / Desktop UI
```

Project structure:

```text
engine/collectors/{memory,disk,network}   Read existing forensic artifacts
engine/parsers/                           JSON / Volatility readers and parser facade
engine/ingestion/                         Case ingestion and parser-run recording
engine/normalization/                     Event validation and normalization
engine/correlation/                       Independent deterministic correlation rules
engine/graph/                             Node / Edge projections
engine/storage/                           Repository protocol + SQLite
api/                                      FastAPI application
desktop/                                  Electron main / preload / renderer
schemas/                                  Pydantic models and generated JSON Schema
samples/sample_case/                      Sample memory / disk / network JSON
samples/cross_source/                     Cross-source forensic sample
tests/                                    pytest verification
docs/                                     Architecture, schema, rules, and verification docs
```

EvidenceMesh uses:

- Python 3.12+
- Pydantic 2
- SQLite
- FastAPI
- Uvicorn
- Electron
- TypeScript

The analysis engine does **not** depend on AI APIs or external language models.

Package-management files:

```text
pyproject.toml
requirements.lock
desktop/package-lock.json
```

---

## Windows Release

The Windows x64 release is distributed as:

```text
EvidenceMesh.Setup.0.4.0.exe
```

The installer contains the required runtime components, so users do not need to manually install:

- Python
- Node.js
- Volatility 3
- TShark

Download:

https://github.com/Kowntaewook/evidence-mesh/releases/latest

The v0.4.0 release also contains:

```text
EvidenceMesh.Setup.0.4.0.exe
EvidenceMesh.CorrespondingSource.0.4.0.zip
Windows-E2E.json
SHA256SUMS.txt
```

The installer may trigger a Windows SmartScreen warning when distributed without code-signing credentials.

See:

- [Windows Packaging](docs/WINDOWS_PACKAGING.md)
- [Release Process](docs/RELEASE_PROCESS.md)
- [Third-Party Licenses](docs/THIRD_PARTY_LICENSES.md)

---

## Development Setup

The following instructions are for the **development environment**.

Requirements:

- Python 3.12+
- Node.js 22.12+
- npm

### Linux / macOS

```bash
cd evidence-mesh

python3 -m venv .venv
source .venv/bin/activate

python -m pip install -r requirements.lock
python -m pip install -e '.[dev]'

# Debian / Ubuntu: external decoder for PCAP input
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

cd desktop
npm ci
cd ..
```

### Windows PowerShell

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

Electron on Linux requires Chromium runtime dependencies such as GTK and NSS.

On Windows, the application should normally be run as a standard user.

---

## Running in Development

Start the API from the repository root:

```bash
python -m uvicorn api.main:app --host 127.0.0.1 --port 8765
```

Then start the Electron desktop application in another terminal:

```bash
cd evidence-mesh/desktop
npm start
```

Development API:

```text
http://127.0.0.1:8765
```

Swagger UI:

```text
http://127.0.0.1:8765/docs
```

OpenAPI schema:

```text
http://127.0.0.1:8765/openapi.json
```

During development, the API terminal must remain running.

The packaged Windows desktop application does not require a separate API terminal. It automatically launches the embedded backend using:

- a random loopback port
- a per-session authentication token

The standalone development API does not require authentication unless the session-token environment variable is configured.

---

## Configuration

| Environment Variable | Default | Purpose |
|---|---|---|
| `EVIDENCEMESH_DB` | `data/evidencemesh.sqlite3` | Analysis database path |
| `EVIDENCEMESH_SAMPLE_DIR` | `samples/sample_case` | Sample evidence directory |
| `EVIDENCEMESH_API` | `http://127.0.0.1:8765` | Local API origin used by the desktop |
| `EVIDENCEMESH_TSHARK` | Bundled Windows path | Preferred TShark executable |
| `EVIDENCEMESH_WORKSPACE` | Packaged AppData | Logs, derived evidence, and memory jobs |
| `EVIDENCEMESH_PYTHON` | Python inside `.venv` | Python path used by desktop E2E tests |

---

## Sample Analysis

1. Open the desktop application.
2. Click **Load Sample Evidence**.
3. Open **Processes**.
4. Select:

```text
powershell.exe
PID 4120
09:31:25
```

5. Click **Analyze Evidence**.

The sample produces:

```text
15 total events
9 related incident events
16 evidence-backed links
```

Click a correlation or graph edge to inspect:

- score
- rule
- explanation
- source artifact
- parser
- raw reference
- provenance

Selecting `notepad.exe` and analyzing it should display:

```text
No matching evidence
```

### Sample Scenario

```text
explorer.exe
    ↓
invoice.zip
    ↓
powershell.exe
    ↓
a.ps1
    ↓
evil.example
    ↓
185.10.10.5:443
```

EvidenceMesh does **not** automatically claim that the ZIP file caused execution.

Instead, it correlates observed evidence such as:

- the Explorer process associated with the ZIP
- PowerShell PPID
- script path
- socket tuple
- DNS response
- PCAP observations

IP addresses and domain names in the sample are inert data.

The repository does not include malware payloads, executable scripts, or large original forensic images.

---

## CLI Sample Analysis

The same sample can be analyzed from the CLI:

```bash
python -m engine.cli sample \
  --db data/demo.sqlite3 \
  --output data/demo-report.json
```

The generated JSON contains:

- case metadata
- correlations
- correlation reasons
- graph
- timeline

Existing report files are not overwritten.

Use a new output filename when rerunning.

Additional options:

```text
--samples
--root
```

The default root event is:

```text
MEM-PS
```

---

## Example Correlation Scores

| Link | Score | Main Evidence |
|---|---:|---|
| PowerShell → `a.ps1` in MFT | 85 | command-line path 50 + time 30 + NTFS 5 |
| Memory socket → PCAP connection | 90 | 5-tuple 60 + time 30 |
| DNS → PCAP connection | 80 | resolved IP 40 + DNS precedence 10 + time 30 |

These are **direct-edge scores**.

EvidenceMesh does not multiply scores across multi-hop paths such as:

```text
PowerShell → socket → DNS
```

and does not represent those paths as direct correlations.

---

## Volatility JSON Import

Place Volatility JSON exports in the same directory:

```text
pslist.json
pstree.json
cmdline.json
netscan.json
dlllist.json
```

Only outputs extracted from the **same memory image** should be merged in one operation.

Example:

```bash
python -m engine.cli import-memory tests/fixtures/volatility \
  --image-id fixture-memory-01 \
  --extracted-at 2026-09-16T09:35:00Z \
  --hostname workstation-01 \
  --volatility-version 2.28.0 \
  --db data/evidencemesh.sqlite3 \
  --output data/volatility-events.json
```

The synthetic fixture contains:

```text
14 rows
↓
8 normalized Events
```

Result:

```text
3 process events
2 socket events
3 DLL events
```

After importing into the same database used by the desktop application:

1. Click **Refresh**
2. Select the newly created case
3. Open **Processes**
4. Click **Analyze Evidence**

For a single Volatility JSON file:

```bash
python -m engine.cli import-memory pslist.json \
  --plugin windows.pslist \
  ...
```

Unknown Volatility versions may be omitted and are stored as `null` with a warning.

Events without an original event timestamp use an explicit `extraction_time` and do not receive temporal correlation scores.

See:

- [Volatility Adapter](docs/VOLATILITY_ADAPTER.md)
- [UI Design](docs/UI_DESIGN.md)

---

## API

| Method | Path | Behavior |
|---|---|---|
| GET | `/health` | Check server and database connectivity |
| POST / GET | `/cases` | Create / list cases |
| GET | `/cases/{case_id}` | Read case and revision |
| POST / GET | `/cases/{case_id}/events` | Add / query Events |
| POST | `/cases/{case_id}/correlate` | Analyze a case |
| GET | `/cases/{case_id}/correlations` | Read stored correlations and reasons |
| GET | `/cases/{case_id}/graph` | Read incident graph |
| GET | `/cases/{case_id}/timeline` | Read UTC timeline |
| POST | `/cases/{case_id}/import/{memory,disk,network}` | Import evidence |
| GET | `/cases/{case_id}/{processes,files,network}` | Query categorized observations |
| GET | `/cases/{case_id}/{imports,parser-runs}` | Read import/parser execution results |
| GET | `/parsers/volatility` | Discover available Volatility plugins |
| POST | `/samples/load` | Create the synthetic sample case |
| GET | `/runtime/dependencies` | Report runtime dependency status |
| GET | `/cases/{case_id}/event-page` | Server-side page/search/view query |
| POST / GET | `/cases/{case_id}/memory-jobs` | Raw-memory analysis jobs |
| POST | `/cases/{case_id}/disk-images/{inspect,import}` | Inspect/import disk-image artifacts |

Example:

```text
/cases/{case_id}/graph?root_event_id=MEM-PS
```

or:

```text
/cases/{case_id}/timeline?root_event_id=MEM-PS
```

Expected errors:

```text
409  Analysis required / duplicate event conflict
404  Missing case or root event
422  Invalid request schema
```

Artifact imports record parser and storage failures in:

```text
ImportReport.status
runs[].error
```

An HTTP 200 response alone does not mean that every parser succeeded.

Adding new evidence invalidates previously computed analysis.

---

## Cross-source Case Import

```bash
python -m engine.cli import-case samples/cross_source \
  --db data/cross-source.sqlite3
```

Use the returned `case_id`:

```bash
python -m engine.cli correlate \
  --db data/cross-source.sqlite3 \
  --case-id CASE_ID

python -m engine.cli timeline \
  --db data/cross-source.sqlite3 \
  --case-id CASE_ID

python -m engine.cli graph \
  --db data/cross-source.sqlite3 \
  --case-id CASE_ID

python -m engine.cli parser-runs \
  --db data/cross-source.sqlite3 \
  --case-id CASE_ID

python -m engine.cli discover-plugins
```

For individual evidence inputs, create a case first:

```bash
python -m engine.cli case-create --name NAME
```

Then import:

```text
memory
mft
usn
prefetch
evtx
amcache
file
pcap
```

Example:

```bash
python -m engine.cli import pcap INPUT \
  --case-id ID \
  --acquisition-id ID \
  --extracted-at ISO_TIME
```

Optional context fields include:

```text
--hostname
--volume-id
--timezone
--mount-point
--logical-path
--recovered-directory
```

Only provide values that are actually known.

See [Case Format](docs/CASE_FORMAT.md) for a complete manifest example.

---

## Desktop Evidence Import

The desktop application supports direct evidence import:

- **Import Memory**
- **Import Disk**
- **Import PCAP**

Memory JSON exports should come from the same memory image.

The raw-memory panel provides:

- image selection
- plugin progress
- cancellation
- result caching

The disk-image panel provides:

- volume discovery
- artifact selection
- read-only extraction

PCAP import optionally accepts a TLS session key log.

A cross-source investigation can correlate evidence such as:

```text
PowerShell PID 4120
a.ps1 command line
a.ps1 file handle
MFT entry
USN entry
Prefetch entry
DNS lookup
TLS observation
memory socket
PCAP flow
```

Keep output files and the EvidenceMesh analysis database outside the original evidence directory.

---

## Verification

Run the Python checks:

```bash
pytest -q
ruff check .
ruff format --check .
python -m build
```

Desktop checks:

```bash
cd desktop

npm run typecheck
npm run build
npm run package
npm run test:e2e
```

`npm run package` creates an executable directory for the current OS / CPU under:

```text
desktop/release/
```

This development package still requires the Python API to be started separately.

The self-contained Windows installer is built with:

```bash
npm run package:win
```

and is additionally verified by GitHub Actions using a real Windows install / run / uninstall workflow.

Linux headless Electron verification uses:

```bash
xvfb-run -a npm run test:e2e
```

Tests use temporary databases and real Uvicorn / Electron processes and clean them up after completion.

Only the root-container E2E runner adds:

```text
--no-sandbox
```

Normal `npm start` does not.

See [docs/VERIFICATION.md](docs/VERIFICATION.md) for detailed results.

---

## Windows Release Verification

The v0.4.0 release pipeline verifies:

```text
Python regression tests
Ruff
Source/license collection
Frozen Python backend
Runtime dependencies
Bundled Volatility
Bundled TShark
TypeScript
NSIS installer creation
Silent installation
Installed Electron application startup
Embedded backend startup
SQLite creation
Loopback authentication
Sample analysis
Correlation
Provenance
Timeline
Incident graph
Disk artifact imports
Read-only NTFS image parsing
PCAP / PCAPNG parsing
HTTP / TLS handling
Clean application shutdown
Backend shutdown
No orphan worker processes
Silent uninstall
Preservation of user evidence
Release SHA-256 manifest
```

The published release also contains:

```text
Windows-E2E.json
```

which records the executed Windows validation checks.

---

## Performance

EvidenceMesh was tested with synthetic normalized event datasets containing:

```text
10,000 events
50,000 events
100,000 events
```

For the 100,000-event run:

```text
Import time:       14.52 s
Correlation time:  11.80 s
Peak memory:       1,425.45 MiB
```

Approximately:

```text
210,000 candidate pairs
```

were evaluated instead of approximately:

```text
4.99995 billion possible pairs
```

These numbers measure normalized-event import and correlation.

They do **not** measure:

- raw forensic image decoding
- full graph-rendering performance

Very dense groups sharing the same identity can still produce many real links.

---

## Limitations

### Raw memory

Raw-memory orchestration is implemented, but:

**NOT VALIDATED WITH REAL MEMORY IMAGE**

Volatility may require matching symbols for a real memory image.

### Disk

Currently unsupported or incomplete:

- E01 reader
- encrypted disk layouts
- deleted registry-cell recovery
- transaction-log replay
- MAM 0x84
- some unsupported disk layouts

### Network

Automatic handling is not currently provided for:

- NAT correction
- clock-skew correction
- device-volume alias inference

TLS decryption requires a matching user-provided session key log.

Without keys, EvidenceMesh records TLS metadata only.

### Interpretation

A high Correlation Score does **not** mean:

- malware
- compromise
- causation

Similarly, observations such as:

```text
psscan mismatch
malfind result
module mismatch
```

are forensic observations and must be interpreted by an analyst.

EvidenceMesh does not use an AI API.

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Event Schema](docs/EVENT_SCHEMA.md)
- [Correlation Rules](docs/CORRELATION_RULES.md)
- [Parser Support](docs/PARSER_SUPPORT.md)
- [Verification](docs/VERIFICATION.md)
- [Windows Packaging](docs/WINDOWS_PACKAGING.md)
- [Release Process](docs/RELEASE_PROCESS.md)
- [Volatility Adapter](docs/VOLATILITY_ADAPTER.md)
- [UI Design](docs/UI_DESIGN.md)
- [Third-Party Licenses](docs/THIRD_PARTY_LICENSES.md)

---

## License

EvidenceMesh source code is licensed under the **MIT License**.

Bundled third-party components retain their original licenses.

See:

[docs/THIRD_PARTY_LICENSES.md](docs/THIRD_PARTY_LICENSES.md)
