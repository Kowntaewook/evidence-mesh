"""Read-only raw memory execution with bounded, cancellable Volatility workers."""

import hashlib
import json
import logging
import os
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from engine.collectors.memory.extended import MemoryImportAdapter
from engine.ingestion.evidence import digest_file, json_loads
from engine.parsers.volatility.registry import discover_plugins
from engine.processes import process_options, terminate_tree
from engine.runtime import volatility_command, workspace_root
from schemas.events import ParserInfo, Provenance, RawReference, Source, SourceArtifact
from schemas.imports import ImportBatch, ParserRun, RunStatus
from schemas.jobs import MemoryJobRequest

TERMINAL = {"SUCCESS", "PARTIAL", "FAILED", "CANCELLED", "UNAVAILABLE"}


def atomic_json(path: Path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.replace(temporary, path)


class MemoryJobs:
    def __init__(self, repository, workspace=None, command=None):
        self.repository = repository
        self.workspace = Path(workspace or workspace_root())
        self.command = command or volatility_command()
        self.jobs, self.cancellations = {}, {}
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="memory-analysis")
        self.directory = self.workspace / "jobs"
        self.directory.mkdir(parents=True, exist_ok=True)
        for path in self.directory.glob("*.json"):
            try:
                job = json_loads(path.read_text())
                if job["status"] not in TERMINAL:
                    job["status"], job["error"] = "CANCELLED", "Previous application session ended"
                    atomic_json(path, job)
                self.jobs[job["job_id"]] = job
            except (ValueError, KeyError):
                logging.getLogger("evidencemesh").warning("Unreadable prior job manifest")

    def start(self, case_id: str, request: MemoryJobRequest):
        self.repository.get_case(case_id)
        path = Path(request.path).expanduser().resolve()
        if path.suffix.lower() not in {".raw", ".mem", ".vmem", ".dmp"}:
            raise ValueError("Select a .raw, .mem, .vmem or .dmp memory image")
        if not path.is_file() or not path.stat().st_size:
            raise ValueError("Memory image must be a nonempty existing file")
        if "windows.dumpfiles" in request.plugins and not request.file_objects:
            raise ValueError("dumpfiles requires explicitly selected FILE_OBJECT virtual addresses")
        job_id = str(uuid4())
        job = {
            "job_id": job_id,
            "case_id": case_id,
            "path": str(path),
            "status": "PENDING",
            "started_at": datetime.now(UTC).isoformat(),
            "completed": 0,
            "total": len(request.plugins),
            "plugins": [{"plugin": name, "status": "PENDING", "cached": False} for name in request.plugins],
            "error": None,
            "report": None,
        }
        with self.lock:
            self.jobs[job_id] = job
            self.cancellations[job_id] = threading.Event()
            self._save(job)
        self.executor.submit(self._execute, job_id, request.model_copy(update={"path": str(path)}))
        return self.get(case_id, job_id)

    def _save(self, job):
        atomic_json(self.directory / (job["job_id"] + ".json"), job)

    def get(self, case_id, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            if not job or job["case_id"] != case_id:
                raise KeyError("Memory analysis job not found in this case")
            return json.loads(json.dumps(job))

    def list(self, case_id):
        self.repository.get_case(case_id)
        with self.lock:
            return [json.loads(json.dumps(j)) for j in self.jobs.values() if j["case_id"] == case_id]

    def cancel(self, case_id, job_id):
        job = self.get(case_id, job_id)
        if job["status"] not in TERMINAL:
            self.cancellations[job_id].set()
        return self.get(case_id, job_id)

    def close(self):
        for cancel in self.cancellations.values():
            cancel.set()
        self.executor.shutdown(wait=True, cancel_futures=False)

    def _update(self, job_id, **values):
        with self.lock:
            self.jobs[job_id].update(values)
            self._save(self.jobs[job_id])

    def _plugin_update(self, job_id, index, **values):
        with self.lock:
            job = self.jobs[job_id]
            job["plugins"][index].update(values)
            job["completed"] = sum(p["status"] not in {"PENDING", "RUNNING"} for p in job["plugins"])
            self._save(job)

    def _execute(self, job_id, request):
        cancel = self.cancellations[job_id]
        runs, exports, cache = [], [], {}
        original = None
        try:
            self._update(job_id, status="HASHING")
            digest = hashlib.sha256()
            image = Path(request.path)
            before = image.stat()
            with image.open("rb") as stream:
                while data := stream.read(1024 * 1024):
                    if cancel.is_set():
                        self._update(job_id, status="CANCELLED")
                        return
                    digest.update(data)
            checksum = digest.hexdigest()
            original = SourceArtifact(
                artifact_id="sha256:" + checksum,
                kind="memory_image",
                path=str(image),
                sha256=checksum,
                size=before.st_size,
                imported_at=datetime.now(UTC),
            )
            directory = self.workspace / "derived" / "memory" / checksum
            directory.mkdir(parents=True, exist_ok=True)
            run_directory = directory / "runs" / job_id
            run_directory.mkdir(parents=True)
            manifest_path = directory / "manifest.json"
            if manifest_path.exists():
                try:
                    cache = json_loads(manifest_path.read_text())
                except ValueError:
                    cache = {}
            discovery = discover_plugins(command=self.command)
            available = {p["plugin"]: p for p in discovery["plugins"]}
            version = discovery["version"]
            self._update(job_id, status="RUNNING", sha256=checksum, derived_directory=str(directory))
            for index, plugin in enumerate(request.plugins):
                run = ParserRun(
                    parser="VolatilityExecution",
                    plugin=plugin,
                    source=Source.MEMORY,
                    status=RunStatus.RUNNING,
                    artifact=original,
                )
                runs.append(run)
                if cancel.is_set():
                    run.status = RunStatus.CANCELLED
                elif not available[plugin]["available"]:
                    run.status, run.error = (
                        RunStatus.UNAVAILABLE,
                        discovery["error"] or "Plugin not installed",
                    )
                else:
                    entry = cache.get(plugin, {})
                    output = directory / entry.get("path", "missing-cache-entry")
                    if not output.resolve().is_relative_to(directory.resolve()):
                        raise ValueError("Cached output path leaves its derived evidence directory")
                    fingerprint = {
                        "version": version,
                        "file_objects": request.file_objects if plugin == "windows.dumpfiles" else [],
                    }
                    cached = bool(
                        version
                        and not request.rerun
                        and entry.get("fingerprint") == fingerprint
                        and output.is_file()
                    )
                    if cached:
                        cached = digest_file(output)[0] == entry.get("sha256")
                    self._plugin_update(job_id, index, status="RUNNING", cached=cached)
                    if cached:
                        run.status = RunStatus.SUCCESS
                        run.warnings.append(
                            "Reused verified output from the same image hash and tool/options"
                        )
                    else:
                        output = run_directory / (plugin + ".json")
                        names = available[plugin]["installed_names"]
                        installed = next((name for name in names if name.startswith(plugin + ".")), names[0])
                        run.command = [
                            *self.command,
                            "-f",
                            str(image),
                            "-r",
                            "json",
                            "-q",
                            "--cache-path",
                            str(self.workspace / "symbols"),
                            "-o",
                            str(run_directory),
                            installed,
                        ]
                        if plugin == "windows.dumpfiles":
                            run.command.extend(["--virtaddr", *request.file_objects])
                        self._invoke(run, output, request.timeout_seconds, cancel)
                        if run.status == RunStatus.SUCCESS:
                            cache[plugin] = {
                                "sha256": digest_file(output)[0],
                                "fingerprint": fingerprint,
                                "path": str(output.relative_to(directory)),
                                "extracted_at": datetime.now(UTC).isoformat(),
                                "command": run.command,
                            }
                            atomic_json(manifest_path, cache)
                    if run.status == RunStatus.SUCCESS:
                        # Validate structured output before allowing the existing adapter to consume it.
                        json_loads(output.read_text(encoding="utf-8"))
                        exports.append((plugin, output))
                run.finished_at = datetime.now(UTC)
                self._plugin_update(job_id, index, status=run.status.value, error=run.error)
                logging.getLogger("evidencemesh").info("parser plugin=%s status=%s", plugin, run.status.value)
            after = image.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("Original memory image changed during analysis")
            recovered = (
                directory / cache["windows.dumpfiles"]["path"]
                if "windows.dumpfiles" in cache
                else run_directory / "unused"
            )
            context = request.context.model_copy(
                update={"tool_version": version, "recovered_directory": str(recovered.parent)}
            )
            batch = MemoryImportAdapter(context).load_exports(exports, expected=[])
            by_plugin = {run.plugin: run for run in runs}
            for parsed in batch.runs:
                executed = by_plugin[parsed.plugin]
                executed.event_count, executed.row_count = parsed.event_count, parsed.row_count
                if parsed.status != RunStatus.SUCCESS:
                    executed.status, executed.error = parsed.status, parsed.error
                executed.warnings.extend(parsed.warnings)
            for event in batch.events:
                # A re-run is a new observation; never overwrite an earlier normalized record.
                event.event_id += ":" + job_id[:8]
                event.metadata.update(memory_job_id=job_id, original_memory_sha256=checksum)
                for reference in event.provenance:
                    if reference.plugin in cache:
                        reference.extraction_timestamp = cache[reference.plugin]["extracted_at"]
                event.provenance.append(
                    Provenance(
                        source_artifact=original,
                        raw_reference=RawReference(
                            artifact_id=original.artifact_id, locator="derived-by:volatility3"
                        ),
                        parser=ParserInfo(name="VolatilityExecution"),
                        tool="volatility3",
                        tool_version=version,
                        memory_image_id=context.acquisition_id,
                        source=Source.MEMORY,
                        acquisition_id=context.acquisition_id,
                        extraction_timestamp=context.extracted_at,
                        row_index=0,
                        raw={"job_id": job_id, "image_sha256": checksum},
                    )
                )
            batch.runs = runs
            report = self.repository.import_batch(self.jobs[job_id]["case_id"], batch)
            for index, run in enumerate(runs):
                self._plugin_update(job_id, index, status=run.status.value, error=run.error)
            self._update(
                job_id,
                status="CANCELLED" if cancel.is_set() else report.status,
                report=report.model_dump(mode="json"),
                finished_at=datetime.now(UTC).isoformat(),
            )
        except Exception as exc:
            run = ParserRun(
                parser="VolatilityExecution",
                source=Source.MEMORY,
                status=RunStatus.FAILED,
                artifact=original,
                error=str(exc),
                finished_at=datetime.now(UTC),
            )
            try:
                self.repository.import_batch(self.jobs[job_id]["case_id"], ImportBatch(runs=[run]))
            finally:
                self._update(job_id, status="FAILED", error=str(exc))

    @staticmethod
    def _invoke(run, output, timeout, cancel):
        partial = output.with_suffix(".partial")
        try:
            with (
                partial.open("w", encoding="utf-8") as stdout,
                tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr,
            ):
                child = subprocess.Popen(
                    run.command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, **process_options()
                )
                began = time.monotonic()
                while child.poll() is None:
                    if cancel.wait(0.05):
                        terminate_tree(child)
                        run.status, run.error = (
                            RunStatus.CANCELLED,
                            "Cancelled by user or application shutdown",
                        )
                        break
                    if time.monotonic() - began > timeout:
                        terminate_tree(child)
                        run.status, run.error = RunStatus.TIMEOUT, f"Plugin exceeded {timeout:g} seconds"
                        break
                run.exit_code = child.returncode
                stderr.seek(0)
                run.stderr = stderr.read(65536) or None
                if run.status == RunStatus.RUNNING:
                    run.status = RunStatus.SUCCESS if child.returncode == 0 else RunStatus.FAILED
                    if child.returncode:
                        run.error = f"Volatility exited with code {child.returncode}"
            if run.status == RunStatus.SUCCESS:
                json_loads(partial.read_text(encoding="utf-8"))
                os.replace(partial, output)
        except (OSError, ValueError) as exc:
            run.status, run.error = RunStatus.FAILED, str(exc)
        finally:
            partial.unlink(missing_ok=True)
