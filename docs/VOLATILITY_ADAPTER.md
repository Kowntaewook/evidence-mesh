# Volatility 3 memory adapter

## Input and compatibility

The structured-export entry point is `MemoryImportAdapter` in `engine/collectors/memory/extended.py`, used by CLI, API and Desktop imports. It consumes **existing JSON exports**. In v0.4, the separate MemoryJobs service runs raw-image plugins and feeds their outputs into this unchanged adapter contract; see [RAW_MEMORY_ANALYSIS.md](RAW_MEMORY_ANALYSIS.md).

The original five-plugin `Volatility3Adapter` and its 14-row → 8-Event regression remain intact. The new adapter composes it with 16 additional parsers. Parser versions now use the synchronized application VERSION; the separately recorded tool version identifies Volatility.

Supported JSON forms include flat row arrays and the Volatility JSON renderer's nested `__children` trees. Parent context is inherited only where the plugin format establishes it. Field aliases, numeric/hex values, aware timestamps and optional nulls are validated. Duplicate JSON keys, nonfinite values, conflicting aliases and malformed rows are errors.

## Plugin support

All 21 canonical plugins were found by **installed Volatility 3 2.28.0** discovery. This proves availability, not successful execution against an image.

| Canonical plugin | Normalized observations |
|---|---|
| windows.pslist | Active process; PID, PPID, creation/exit, EPROCESS observation |
| windows.pstree | Process and scoped parent/child identities |
| windows.cmdline | Process command-line observation merged conservatively |
| windows.netscan | PID-owned TCP/UDP socket; actual addresses/state/time |
| windows.dlllist | Process-owned module/file, base/size/load time |
| windows.psscan | Separate scan process; pslist_found/psscan_found signal |
| windows.envars | Process environment names/values |
| windows.handles | Raw object type, handle/object addresses, access/name; File relationships |
| windows.filescan | FILE_OBJECT, observed path/name and memory offset |
| windows.vadinfo | Typed region boundaries/protection/tag/commit/private/file |
| windows.malware.malfind | suspicious_memory_region, hex/disassembly previews |
| windows.svcscan | Service name/state/start/binary/PID/DLL |
| windows.svclist | Same service contract, where installed |
| windows.registry.amcache | Memory-sourced registry/file observations |
| windows.registry.userassist | Memory-sourced execution-related registry observations |
| windows.shimcachemem | Memory-sourced cached file path/time/flags |
| windows.modules | Loaded kernel module observation |
| windows.modscan | Scanned kernel module and list-comparison signal |
| windows.driverscan | Driver address/start/size/name/service key |
| windows.callbacks | Callback type/address/module/symbol |
| windows.dumpfiles | Existing recovered-file bytes: SHA-256/size/output/FILE_OBJECT/PID |

Aliases include older `windows.malfind`, `windows.amcache` and class-suffixed installed names. The registry is in [registry.py](../engine/parsers/volatility/registry.py). Discovery runs the selected executable with `--help` as an argument array and a timeout. It captures stderr and reports unavailable plugins individually. It never assumes that one namespace is present everywhere.

Missing expected export = SKIPPED; absent discovered plugin = UNAVAILABLE; invalid input = FAILED; imported valid input = SUCCESS. Available exports can still be parsed without an installed Volatility binary because they are already generated data.

## Process and forensic semantics

Process observations merge only when identity evidence is compatible. psscan remains a separate observation and compares against pslist. Unknown/ambiguous owners remain scoped unresolved identities. PID reuse is not merged. Missing event timestamps use explicit extraction_time, not fabricated creation dates.

Memory-derived registry evidence keeps source=memory. VAD/malfind/scan-only/module mismatch results are descriptive signals, never malware/rootkit labels. Drivers and callbacks have normalized/graph observations; dedicated scored cross-source kernel ownership rules are **PARTIAL**.

dumpfiles requires `recovered_directory`. Each referenced output must exist within that explicit directory; traversal outside it fails. Hashes and size are calculated from actual recovered bytes. Memory image ID, plugin row, offsets, FILE_OBJECT, owner and output path are preserved. The adapter does not claim to have performed the original extraction.

## Usage

```bash
python -m engine.cli discover-plugins
python -m engine.cli import memory samples/cross_source/memory/volatility \
  --db data/case.sqlite3 --case-id CASE_ID \
  --acquisition-id cross-memory --extracted-at 2026-09-16T09:35:00Z \
  --hostname workstation-01 --tool-version 2.28.0 \
  --recovered-directory samples/cross_source/memory/recovered
```

Supply the actual acquisition/tool facts. Tool version may be omitted when unknown. Original `import-memory --image-id ... --volatility-version ...` remains available and routes through the full pipeline.

## Validation

Original five-plugin tests remain byte-for-byte unchanged. Each additional parser has normal, malformed and optional-field tests, plus combined ownership/provenance/recovery tests. An actual installed Volatility JsonRenderer was exercised with a synthetic TreeGrid to check nested/int/hex/time/null serialization. The renderer contract is documented in the [official Volatility source](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/cli/text_renderer.html).

**NOT VALIDATED WITH REAL MEMORY IMAGE**: real-image validation is explicitly outside this release task. Synthetic plugin rows and actual renderer compatibility do not establish real-image plugin compatibility.
