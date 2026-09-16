"""Case-level import orchestration. Adapters remain independent of correlation."""

from datetime import UTC, datetime
from pathlib import Path

from engine.collectors.disk.artifacts import DiskArtifactAdapter
from engine.collectors.memory.extended import MemoryImportAdapter
from engine.collectors.network.pcap import PcapAdapter
from engine.ingestion.evidence import ArtifactError, json_loads
from engine.parsers.volatility.registry import filename_plugin
from schemas.events import Source
from schemas.imports import ArtifactContext, ImportBatch, ImportRequest, ParserRun, RunStatus


class ImportService:
    def __init__(self, repository):
        self.repository = repository

    def import_evidence(self, case_id: str, kind: str, request: ImportRequest):
        self.repository.get_case(case_id)
        path = Path(request.path).expanduser().resolve()
        source = (
            Source.MEMORY
            if kind == "memory"
            else Source.NETWORK
            if kind in {"pcap", "network"}
            else Source.DISK
        )
        try:
            database = Path(self.repository.path).resolve()
            if database == path or path.is_dir() and database.is_relative_to(path):
                raise ArtifactError("Analysis database must be outside the input evidence directory")
            if kind == "memory":
                adapter = MemoryImportAdapter(request.context)
                if path.is_dir():
                    batch = adapter.load_directory(path, request.plugins)
                else:
                    plugin = request.format or filename_plugin(path.stem)
                    batch = adapter.load_exports([(plugin, path)], request.plugins)
            elif source == Source.NETWORK:
                batch = PcapAdapter(request.context).load_file(path)
            else:
                artifact = request.format if kind == "disk" else kind
                mft = self.repository.query_events(case_id, artifact_type="$MFT") if artifact == "usn" else []
                adapter = DiskArtifactAdapter(request.context, mft)
                if path.is_dir():
                    files = sorted(file for file in path.rglob("*") if file.is_file())
                    if not files:
                        raise ArtifactError(f"No input files in {path}")
                    batch = ImportBatch()
                    for file in files:
                        result = adapter.load_file(file, artifact)
                        batch.events.extend(result.events)
                        batch.runs.extend(result.runs)
                else:
                    batch = adapter.load_file(path, artifact)
        except (ValueError, OSError) as exc:
            batch = ImportBatch(
                runs=[
                    ParserRun(
                        parser=f"{kind}Import",
                        source=source,
                        status=RunStatus.FAILED,
                        error=str(exc),
                        finished_at=datetime.now(UTC),
                    )
                ]
            )
        return self.repository.import_batch(case_id, batch)

    def import_case(self, case_id: str, path: Path, context: ArtifactContext | None = None):
        path = Path(path).resolve()
        manifest_path = path / "case.json" if path.is_dir() else path
        root = manifest_path.parent
        if manifest_path.exists():
            manifest = json_loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict) or not isinstance(manifest.get("imports"), list):
                raise ArtifactError("Case manifest requires an imports array")
            common = manifest.get("context", context.model_dump(mode="json") if context else {})
            entries = manifest["imports"]
        else:
            if context is None:
                raise ArtifactError("Directory without case.json requires explicit acquisition context")
            common, entries = context.model_dump(mode="json"), []
            memory = root / "memory" / "volatility"
            if memory.is_dir():
                entries.append({"kind": "memory", "path": str(memory.relative_to(root))})
            disk = root / "disk" / "artifacts"
            if disk.is_dir():
                for kind in ("mft", "usn", "prefetch", "evtx", "amcache"):
                    entries.extend(
                        {"kind": kind, "path": str(file.relative_to(root))}
                        for file in sorted(disk.glob(kind + "*"))
                    )
            network = root / "network"
            if network.is_dir():
                entries.extend(
                    {"kind": "pcap", "path": str(file.relative_to(root))}
                    for file in sorted(network.iterdir())
                    if file.suffix.lower() in {".pcap", ".pcapng"}
                )
        if not entries:
            raise ArtifactError("No evidence inputs in case")
        requests = []
        for entry in entries:
            if not isinstance(entry, dict) or "kind" not in entry or "path" not in entry:
                raise ArtifactError("Each case input requires kind and path")
            source = Path(entry["path"])
            if not source.is_absolute():
                source = (root / source).resolve()
                if not source.is_relative_to(root):
                    raise ArtifactError("Relative case input escapes the evidence directory")
            values = {**common, **entry.get("context", {})}
            if values.get("recovered_directory"):
                recovered = Path(values["recovered_directory"])
                if not recovered.is_absolute():
                    values["recovered_directory"] = str((root / recovered).resolve())
            requests.append(
                (
                    entry["kind"],
                    ImportRequest(
                        path=str(source),
                        format=entry.get("format"),
                        plugins=entry.get("plugins"),
                        context=ArtifactContext.model_validate(values),
                    ),
                )
            )
        # The manifest order is authoritative; place MFT before USN to enrich historical references.
        return [self.import_evidence(case_id, kind, request) for kind, request in requests]
