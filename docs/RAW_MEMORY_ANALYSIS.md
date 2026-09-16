# Raw memory execution

Raw-memory orchestration is **IMPLEMENTED**. It is
**NOT VALIDATED WITH REAL MEMORY IMAGE**.

Create/select a case, enter the acquisition ID and aware extraction time, select
plugins in the raw-memory panel and choose a `.raw`, `.mem`, `.vmem` or `.dmp`
image. Twenty supported plugins are selected by default. `windows.dumpfiles` is
excluded from the default and requires explicit FILE_OBJECT addresses. Choosing
a memory image never mounts or writes it.

The backend hashes the image, discovers installed plugin class names from actual
Volatility help output, runs each available plugin using an argument array and
the bundled backend's `--volatility` mode, then passes JSON output to the existing
MemoryImportAdapter. Progress records are persisted and the UI polls them. One
plugin's failure does not discard successful outputs.

Statuses include PENDING, RUNNING, SUCCESS, FAILED, UNAVAILABLE, TIMEOUT and
CANCELLED. The API accepts per-plugin timeout values between 0.1 and 3,600
seconds, with a default of 300 seconds. Cancelling terminates the active process
tree and marks pending plugins cancelled. Jobs use one worker per backend.

```text
POST /cases/{id}/memory-jobs
GET  /cases/{id}/memory-jobs
GET  /cases/{id}/memory-jobs/{job_id}
POST /cases/{id}/memory-jobs/{job_id}/cancel
```

Requests contain `path`, `context`, optional `plugins`, `timeout_seconds`, `rerun`
and explicit `file_objects`. The import API's acquisition context applies. Jobs
are scoped to their case; invalid paths, unsupported suffixes and unrequested
dumpfiles extraction fail explicitly.

Cache identity includes image SHA-256, actual Volatility version and plugin
options. Cached outputs are hash-verified before reuse. Re-run creates a new job
directory and retains prior output files so existing provenance does not point
at overwritten data. Events link both structured output and the original image
hash; fallback extraction timestamps are labeled and not treated as event time.

Tests use an inert subprocess worker to verify argument construction, partial
failure, missing plugins, timeout, cancellation, cache, re-run and provenance.
The Windows installed test invokes actual bundled Volatility on an explicitly
invalid image and requires a truthful failure. Neither test is real-image
analysis. Actual images can require matching Windows symbols, supported layers
and substantial time/space; plugin availability is not an analysis-success claim.
