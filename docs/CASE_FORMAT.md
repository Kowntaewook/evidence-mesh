# Case format and import workflow

A case may contain any nonempty subset of Memory, Disk and Network. All three sources are not required. Store the analysis DB outside the evidence directory.

```text
case/
  case.json
  memory/
    volatility/pslist.json ... handles.json ...
    recovered/...
  disk/artifacts/
    mft.json
    usn.json
    prefetch/
    evtx/
    amcache/
  network/traffic.pcapng
```

A memory.raw file may be retained with evidence, but EvidenceMesh consumes the existing Volatility exports; it does not automatically analyze that image.

## Manifest

```json
{
  "name": "Example case",
  "context": {
    "acquisition_id": "case-01",
    "extracted_at": "2026-09-16T09:35:00Z",
    "hostname": "workstation-01",
    "volume_id": "volume-C"
  },
  "imports": [
    {
      "kind": "memory",
      "path": "memory/volatility",
      "context": {
        "acquisition_id": "memory-01",
        "recovered_directory": "memory/recovered"
      }
    },
    {"kind": "mft", "path": "disk/artifacts/mft.json"},
    {"kind": "usn", "path": "disk/artifacts/usn.json"},
    {
      "kind": "pcap",
      "path": "network/traffic.pcapng",
      "context": {"acquisition_id": "capture-01", "hostname": null}
    }
  ]
}
```

Entries override common context. acquisition_id and aware extracted_at are required. Optional values: hostname, tool_version, volume_id, timezone, recovered_directory, mount_point, logical_path. Network hostname=null avoids asserting that a capture sensor is a client host.

Kinds: memory, mft, usn, prefetch, evtx, amcache, file, pcap; generic disk/network routes use format or supported routing. Entry `plugins` can select memory exports. Relative evidence paths must stay inside the case directory; explicit absolute paths are accepted. Relative recovered_directory resolves from the manifest directory, and dumpfiles outputs must stay inside that root.

Manifest order is authoritative. Put MFT before USN to enrich references. Independent valid imports remain available if another parser is unavailable/failed; inspect each run rather than assuming the entire case succeeded.

Without a manifest, explicit context can drive conventional directory discovery under memory/volatility, disk/artifacts and network. Explicit manifests are preferable for acquisition boundaries, timezone and volume mappings. See [the complete fixture manifest](../samples/cross_source/case.json).

## CLI

```bash
python -m engine.cli import-case samples/cross_source --db data/case.sqlite3
python -m engine.cli correlate --db data/case.sqlite3 --case-id CASE_ID
python -m engine.cli timeline --db data/case.sqlite3 --case-id CASE_ID
python -m engine.cli graph --db data/case.sqlite3 --case-id CASE_ID
python -m engine.cli parser-runs --db data/case.sqlite3 --case-id CASE_ID
```

For separate imports, first `case-create --name NAME --db DB`, then `import KIND PATH --db DB --case-id ID --acquisition-id ID --extracted-at TIME`. Original sample/import-memory commands remain compatible. Output files use exclusive creation and are not overwritten.

## Local API / Desktop

POST /cases creates the case. POST /cases/{id}/import/memory, /disk or /network accepts:

```json
{
  "path": "/absolute/evidence/mft.json",
  "format": "mft",
  "context": {
    "acquisition_id": "disk-01",
    "extracted_at": "2026-09-16T09:35:00Z"
  }
}
```

The returned ImportReport includes imported count, status and runs. HTTP 200 can carry a parser failure report. GET /cases/{id}/parser-runs and /imports exposes the audit. The API must run locally with access to the selected filesystem paths.

Desktop Case → artifact context → Import Memory / Import Disk / Import PCAP uses native file/folder selection and these same routes. For content files, select the file format and supply its original logical path if known. Acquisition/time inputs are required; optional host/volume/timezone/recovered-directory fields remain explicit.
