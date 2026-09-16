# Windows packaging and installed validation

The v0.4 target is Windows 10/11 x64 and a single
`EvidenceMesh.Setup.0.4.0.exe`. Windows execution is **NOT YET VALIDATED**.
Publication currently fails with GitHub `403 Resource not accessible by
integration` for `Kowntaewook/evidence-mesh`; the connection lists only the
`APEX-digtal-forensic-tool` organization. A local build definition is not a
successful Windows build or installed E2E result.

## Build

On a Windows build machine with Python 3.12, Node 24, Git and 7-Zip:

```powershell
python -m pip install -r requirements.lock -r packaging/requirements-build.txt -e ".[dev]"
npm ci --prefix desktop
python scripts/sync_version.py --check
python scripts/acquire_tshark.py
$env:PATH = "$pwd\dist\tshark;$env:PATH"
python scripts/prepare_windows_fixtures.py
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python scripts/package_sources.py
pyinstaller --noconfirm --clean packaging/backend.spec
python scripts/backend_smoke.py dist/evidencemesh-backend/evidencemesh-backend.exe --tshark dist/tshark/tshark.exe
npm run typecheck --prefix desktop
npm run package:win --prefix desktop
node desktop/tests/installed-windows.cjs
python scripts/assemble_release.py
```

Build tools are needed by the maintainer, not by the end user. Acquisition checks
the pinned upstream SHA-256 before unpacking; it does not execute the portable
Wireshark installer. All 40 PE files in TShark's import/delay-import closure are
checked against the DLL inventory. Source acquisition retains 35 native source
archives and matching Python dependency source distributions with build recipes.

## Installed layout and lifecycle

```text
EvidenceMesh.exe
resources/
  app.asar
  backend/evidencemesh-backend.exe
  backend/_internal/                 Python, plugins, data and dependencies
  tshark/tshark.exe                  offline decoder and required DLLs/data
  third-party-licenses/              exact notices and source inventory
%APPDATA%/EvidenceMesh/
  evidencemesh.sqlite3
  runtime.json                       address, PID, version; no session token
  logs/{desktop,backend}.log
  memory/                            image-hash cache and immutable job outputs
  derived/{ntfs,network}/             extracted artifacts and bodies
```

Electron spawns its own backend, which binds a reserved random loopback socket
and reports its address on stdout. Startup verifies version and instance ID with
a fresh session token. It opens the interface after health succeeds. Other local
requests without the token receive 401. The IPC bridge validates methods, routes
and the top-level renderer origin. Sandbox, context isolation, disabled Node
integration and blocked navigation remain enabled.

Backend startup has a 45-second timeout and reports a friendly dialog with a log
path and copy button. Parent stdin EOF/quit requests graceful shutdown; Electron
uses bounded tree termination as a fallback. A Windows kill-on-close Job Object
contains backend descendants, including Volatility workers, for abrupt backend
exit. Windows execution of these lifecycle paths remains a required CI gate.

The installer supports silent `/S` installation and uninstallation. Removing the
program intentionally retains the user's database, logs and derived evidence.
Do not write evidence or a database into the installation directory.

## Validation contract

`backend_smoke.py` runs the frozen executable's self-test, verifies real imports
and packaged JSON data, executes Volatility help/plugin discovery, starts a
loopback API, verifies SQLite/health and closes it through the parent pipe.

`installed-windows.cjs` installs the NSIS artifact and launches the **installed**
executable with PATH restricted to Windows System32. It asserts packaged state,
version, actual executable/resource paths, embedded dependencies, authenticated
health, SQLite, sample UI/correlations/provenance/timeline/graph, raw disk imports,
NTFS extraction, actual PCAP/PCAPNG protocols, TLS with/without supplied keys,
native raw-memory selection and truthful invalid-image failure. It checks source
hashes, closes the app, checks remaining app/backend processes and the port, and
uninstalls. It emits a report, screenshot and logs even if later checks fail.

These inputs include generated inert fixtures and hash-pinned public Dissect
EVTX/Amcache samples. No real memory image is included or claimed validated.

## Signing

`CSC_LINK` and `CSC_KEY_PASSWORD` GitHub secrets enable electron-builder signing.
Without them the Windows artifact is unsigned and may trigger SmartScreen.
Signing keys are not required to build a modified unsigned installer. This work
does not claim a signed binary or certificate verification.

The workflow and release gates are documented in [RELEASE_PROCESS.md](RELEASE_PROCESS.md).
