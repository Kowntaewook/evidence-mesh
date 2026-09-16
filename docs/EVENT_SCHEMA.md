# Unified Event Schema v1.0 — additive v0.3 extensions

Canonical contracts: [events.py](../schemas/events.py), [imports.py](../schemas/imports.py), [results.py](../schemas/results.py). JSON Schemas are regenerated with `python scripts/export_schemas.py`. Event schema_version stays **1.0**; existing fields and defaults remain compatible.

## Event fields

Required: `event_id`, timezone-aware `timestamp`, `source` (memory/disk/network), and extensible `type`. Optional observations must not be invented to fill a model.

| Field | Meaning |
|---|---|
| artifact_type | Specific plugin/artifact/protocol classification |
| timestamp_precision / timestamp_uncertainty | Nonnegative seconds; unknown precision may be null |
| timestamp_semantics | event_time, process_creation, socket_creation, module_load, extraction_time, file_creation/modification/access, registry_write, process_execution, flow_start |
| hostname / user | Observed target host and user/SID/domain, not implicitly the analyst or sensor |
| process / file / network | Core typed evidence; extensions below |
| module / handle / memory_region / service | Memory observations |
| registry / driver / callback | Registry-derived and kernel observations |
| prefetch / event_log / journal | Disk-specific structured evidence |
| hash | Content SHA-256 and optional SHA-1 |
| source_artifact / parser / raw_reference / raw | Representative source and locator |
| provenance | Every contributing source row and acquisition/tool context |
| attributes / metadata | JSON-valued compatibility and adapter-specific metadata |

All nested models forbid unknown fields. PID, ports, sizes and counts validate numeric bounds; IP fields validate actual IP addresses. UTC normalization does not infer a timezone from the machine. Ambiguous local timestamps fail unless resolved by the input. Event flow end cannot precede event start.

## Process and file

Process retains PID, PPID, name, executable path, command line, creation_time, instance_id and parent_instance_id; adds **exit_time** and **environment**. Exit before creation is invalid. Unknown owner identity stays unresolved. A PID alone does not establish the same process. A memory-scoped identity can bridge independent disk process creation only on known matching host/PID/creation time.

File adds size, volume_id, record_number, sequence_number, parent_record/parent_sequence, allocated, flags, SI/FN timestamp dictionaries and file_object. Existing path/name/sha256/references remain. File references preserve full observed strings, not resolved analyst paths.

`file.sha256` / `hash.sha256` identify content. `source_artifact.sha256` identifies the artifact container/export. SHA-1 from Amcache is retained but is not substituted for the exact-SHA-256 rule.

## Addresses and artifact fields

New addresses (handles, FILE_OBJECT, VAD, driver, callback) are hexadecimal strings to avoid JavaScript integer rounding. Existing module.base_address integer remains compatible, with base_address_hex added. Electron's API JSON reader preserves unsafe integers as exact decimal display strings; the Python/SQLite models keep original values.

| Model | Selected fields |
|---|---|
| HandleInfo | value, object_address, raw type, name, granted_access |
| MemoryRegion | start/end, protection, tag, commit, private_memory, mapped_file, hex/disassembly previews |
| ServiceInfo | name, display_name, state, start_type, binary_path, pid, service_dll |
| RegistryInfo | artifact, hive, key/value, last_write_time, run_count |
| ModuleInfo | name, path, base_address/base_address_hex, size, observation |
| DriverInfo / CallbackInfo | name/path/start/size/object/service key; type/address/module/symbol |
| PrefetchInfo | executable/path, prefetch_hash, run_count, execution_times, directories, volumes |
| EventLogInfo | event_id, provider, channel, record_id, computer |
| JournalInfo | usn, reason flags, source_info, original file/parent references |

A psscan-only observation or malfind region is a signal. `suspicious_memory_region` is not a malware verdict.

## Network

Core fields retain src/dst IP/port/protocol, state, DNS name and resolved addresses. Add end_time, packet/byte counts, stream ID, observed TCP flags, DNS query type/response/ID, HTTP and TLS structures.

HTTP stores method, host, URI, user agent, response status and content type when visible. TLS stores SNI, version and established client/server orientation when a ClientHello supplies it. Port 443 alone creates no TLS observation.

Flow orientation is the first observed wire direction; both directions aggregate into one stream/tuple. DNS responses retain wire direction and an explicit response flag. Raw packet timestamps/frame numbers remain available.

## Provenance and parser runs

SourceArtifact adds size and imported_at to ID/kind/path/SHA-256. Provenance contains the exact source artifact, matching raw locator, parser, tool/version/plugin, image/acquisition ID, source, extraction timestamp, row index and raw JSON. Unknown tool versions remain null.

ArtifactContext requires acquisition_id/extracted_at; optional hostname, tool_version, volume_id, timezone, recovered_directory, mount_point and logical_path are supplied by the caller.

ParserRun stores SUCCESS/FAILED/UNAVAILABLE/SKIPPED, start/end, row/event counts, error, warnings, stderr, exit_code, command array and input artifact. An ImportReport must be checked for status; HTTP 200 alone is not import success.

## Analysis output

Each reason contains rule, signed score, description and relevant fields. Correlation `raw_score` is the signed sum; `score` is clamped to 0–100. Rule version is 0.3.0. Rejected impossible pairs do not create stored edges.

Graph nodes are typed; edges include reasons, score, timestamp, source_events, provenance and support_count. Aggregated observed edges retain all supporting provenance and the strongest direct reason set. Score is never AI confidence or probability.
