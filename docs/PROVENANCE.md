# Provenance and evidence integrity

Every new artifact import records input **SHA-256, byte size, absolute path and imported_at**. Original evidence is read-only; DB/reports/intermediate output belong outside the evidence directory. ImportService rejects a case DB inside its input evidence directory. The live API verification rehashed inputs after all imports and found them unchanged.

## Traceability

A normalized Event retains representative source_artifact/parser/raw_reference/raw fields and a provenance array. Each contributing row includes artifact ID/hash/path/size, record/offset/frame/JSON locator, parser identity/version, external tool/version/plugin when known, acquisition/image ID, extraction timestamp, source and raw fields.

Memory process merge preserves every contributing plugin row. Disk raw readers retain record and byte locators; exports retain row/pointer locators. Network events retain frame references; flow raw data contains every contributing frame number. Graph edges reference source Event IDs and provenance. Correlation reasons identify the fields used.

Parser-run records retain success/failure/unavailable/skipped status, input artifact, counts, times, command array, exit code, stderr, warnings and error. Failed imports are inspectable in the same case. Unknown tools/versions/time values remain unknown.

## Separate hash meanings

- Export/container hash identifies the file actually read.
- Memory image ID is acquisition context; no image hash is invented from its export.
- Recovered file and disk-content SHA-256 are calculated from actual bytes and may support exact-content correlation.
- Prefetch hash and Amcache SHA-1 are retained in their own fields and are not treated as SHA-256.

dumpfiles verifies outputs inside an explicit recovered_directory. It records output path, source image ID, plugin row, FILE_OBJECT/offset, PID and verified content size/hash. The original extraction operation is external.

## Time and interpretation

Event time, process/socket/module time, file/registry time and extraction time have distinct semantics. Normalized UTC does not imply synchronized source clocks. Precision and uncertainty are explicit seconds; extraction-time fallbacks do not earn temporal points. No automatic clock-skew correction is performed.

Source=memory/disk/network describes the acquisition source, not the apparent artifact type. Memory-derived Amcache remains memory; disk Amcache remains disk. Raw rows are observations, not proof of causation or maliciousness.

## Limits

Hashes establish byte identity at read/import time, not authenticity, custody before import or tamper-proof storage after import. SQLite audit data is local and is not cryptographically signed. A file concurrently modified while being read is not protected by a forensic image snapshot. This application does not replace acquisition/custody procedures.

Schema and reader validation reject duplicate JSON keys, invalid CSV structure, conflicting aliases, invalid addresses/numbers and malformed timestamps. Original 64-bit addresses use hexadecimal typed fields; Electron preserves unsafe JSON integers as decimal display strings. New artifact imports are read by Python; users of legacy arbitrary JSON imports should prefer string addresses and the typed schema.
