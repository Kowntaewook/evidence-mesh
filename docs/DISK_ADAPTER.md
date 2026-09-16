# Disk adapters

`DiskArtifactAdapter(kind, ArtifactContext)` accepts a file or supported directory. Raw readers are separated in [raw.py](../engine/collectors/disk/raw.py); export normalization is in [artifacts.py](../engine/collectors/disk/artifacts.py). Output is source=disk regardless of the external parser used.

## Actual input support

| Artifact | Raw reader | Export reader | Limits |
|---|---|---|---|
| $MFT | dissect.ntfs FILE records; 1024/2048/4096-byte layouts with fixups | JSON/CSV, MFTECmd-style aliases | Extracted MFT, not whole disk image mounting |
| $UsnJrnl | USN_RECORD v2 with length/name bounds | JSON/CSV reason/reference fields | v3/v4 UNAVAILABLE |
| Prefetch | Bounded uncompressed SCCA layouts 17/23/26/30/31 | JSON/CSV, PECmd-style aliases | MAM compressed files UNAVAILABLE; raw v30 synthetic fixture tested, other layouts lack real-file validation |
| EVTX | python-evtx, file/chunk checks, 3.1/3.2 headers | Event XML and JSON/CSV | No damaged/deleted-record carving |
| Amcache | dissect.regf, modern InventoryApplicationFile and legacy Root/File | JSON/CSV, AmcacheParser-style aliases | No transaction-log replay or deleted-cell recovery |
| Content file | Read actual bytes and calculate SHA-256/size | Not an export interpretation | Original logical path only if explicitly supplied |

Install `pip install -e '.[forensics]'` for raw dependencies. Missing dependency/recognized unsupported format reports UNAVAILABLE. Corrupt/truncated/schema-invalid evidence reports FAILED. A valid parser result is never fabricated after an error.

## Normalized meaning

MFT preserves record/sequence, parent reference, filename, size, allocated flag, flags and separate SI/FN timestamps. Parent path reconstruction needs valid parent sequence and an explicitly supplied mount point. Allocation state alone does not invent a deletion time. Unknown full paths remain unknown.

USN retains USN, recorded time, reason flags, source info, original 64-bit reference and decomposed record/sequence. FILE_CREATE, FILE_DELETE, DATA_EXTEND, DATA_OVERWRITE, rename-old/new, CLOSE and BASIC_INFO_CHANGE are retained. Joining MFT requires matching host/volume/record/sequence and compatible name. Import MFT before USN for enrichment; manifest order is authoritative.

Prefetch stores executable/hash/run count/execution times/referenced files/directories/volumes. Execution observations use recorded run times. A prefetch hash is not a content cryptographic hash. Name-only process matching is time bounded; known conflicting full paths reject a match.

EVTX mapping is provider-aware: Security 4688, Sysmon process/network/image/file/registry observations and Service Control Manager service installation map available fields. Other events, including logon/PowerShell records without a specialized mapping, remain structured event-log observations with raw EventData/XML. System/Execution ProcessID is not silently treated as the subject process. Event IDs are never maliciousness verdicts.

Amcache key times retain registry-write semantics. File path/size/SHA-1 are preserved when recorded; registry presence does not prove execution. Memory-derived Amcache remains a separate source=memory observation.

## Export contract

Use UTF-8 JSON row arrays or CSV with a header; embedded list fields accept documented JSON/list exports. Required fields and recognized aliases are shown in `tests/fixtures/disk` and `samples/cross_source/disk/artifacts`. Aliases cover tested MFTECmd/PECmd/AmcacheParser-style fields; arbitrary exporter versions are not universally supported. Conflicting aliases, extra/missing CSV cells, duplicate JSON keys, invalid numbers and invalid timestamps fail explicitly.

Aware timestamps normalize to UTC. Naive export timestamps require an explicit `timezone`; ambiguous daylight-saving times are rejected. Source byte offsets, records, CSV rows/JSON pointers and original fields remain provenance. All inputs are opened read-only.

```bash
python -m engine.cli import mft PATH --db data/case.sqlite3 --case-id CASE_ID \
  --acquisition-id disk-01 --extracted-at 2026-09-16T09:35:00Z \
  --hostname workstation-01 --volume-id volume-C --mount-point 'C:\'
python -m engine.cli import usn PATH --db data/case.sqlite3 --case-id CASE_ID \
  --acquisition-id disk-01 --extracted-at 2026-09-16T09:35:00Z
```

For actual content use `import file PATH --logical-path ORIGINAL_PATH` with the same context flags.

## Validation

44 disk tests cover normal/malformed/optional exports and raw fixtures. Four public binary artifacts were separately parsed: modern/legacy Amcache **222/69** Events; Security/TestLogX EVTX **759/5** Events. A public compressed Prefetch correctly returned UNAVAILABLE.

The public files come from [Fox-IT Dissect's test data](https://github.com/fox-it/dissect.target/tree/main/tests/_data/plugins/os/windows); URLs, sizes and SHA-256 are recorded in `data/compatibility/sources.json`. They are compatibility fixtures, not an independently validated incident ground truth. Raw MFT/USN/SCCA validation uses constructed binary fixtures. Whole disk image analysis: **NOT VALIDATED WITH REAL IMAGE**.

Reader references: [Dissect NTFS API](https://docs.dissect.tools/en/latest/api/dissect/ntfs/index.html), [libyal SCCA format](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc).
