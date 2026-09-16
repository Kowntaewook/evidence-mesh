import argparse
import json
import sys
from pathlib import Path

from engine.collectors.memory.extended import MemoryImportAdapter
from engine.ingestion.service import ImportService
from engine.parsers.volatility.registry import discover_plugins
from engine.parsers.volatility.rows import VolatilityImportError
from engine.sample import DEFAULT_SAMPLE_DIR, load_sample
from engine.service import AnalysisService
from engine.storage import SQLiteRepository
from schemas.imports import ArtifactContext, ImportRequest
from schemas.results import AnalysisRequest, CaseCreate


def run_sample(args):
    events = load_sample(args.samples)
    repository = SQLiteRepository(args.db)
    case = repository.create_case(CaseCreate(name="Sample Investigation", description="Synthetic sample"))
    repository.add_events(case.case_id, events)
    service = AnalysisService(repository)
    result = service.analyze(case.case_id, AnalysisRequest(root_event_id=args.root))
    report = {
        "case": repository.get_case(case.case_id).model_dump(mode="json"),
        "analysis": result.model_dump(mode="json"),
        "graph": service.graph(case.case_id, args.root).model_dump(mode="json"),
        "timeline": service.timeline(case.case_id, args.root).model_dump(mode="json"),
    }
    if args.output:
        # Exclusive create avoids overwriting evidence or a previous report.
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2, ensure_ascii=False)
    print(
        json.dumps(
            {
                "case_id": case.case_id,
                "status": result.status,
                "events": len(events),
                "correlations": result.correlation_count,
                "root": args.root,
            },
            indent=2,
        )
    )


def run_import(args):
    context = ArtifactContext(
        acquisition_id=args.image_id,
        extracted_at=args.extracted_at,
        hostname=args.hostname,
        tool_version=args.volatility_version,
        recovered_directory=args.recovered_directory,
    )
    adapter = MemoryImportAdapter(context)
    if args.input.is_dir():
        if args.plugin:
            raise VolatilityImportError(
                "--plugin is for a single JSON file; directory names identify plugins"
            )
        result = adapter.load_directory(args.input)
    else:
        if not args.plugin:
            raise VolatilityImportError("A single JSON file requires --plugin windows.<name>")
        result = adapter.load_exports([(args.plugin, args.input)])
    if args.output and args.output.exists():
        raise VolatilityImportError(f"Output already exists; refusing to overwrite: {args.output}")
    repository = SQLiteRepository(args.db)
    if args.case_id:
        case = repository.get_case(args.case_id)
    else:
        case = repository.create_case(
            CaseCreate(name=args.name, description=f"Memory exports: {args.image_id}")
        )
    report = repository.import_batch(case.case_id, result)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as output:
            json.dump(
                [event.model_dump(mode="json") for event in result.events],
                output,
                indent=2,
                ensure_ascii=False,
            )
    print(
        json.dumps(
            {
                "case_id": case.case_id,
                **report.model_dump(mode="json"),
                "input_files": len(result.runs),
                "input_rows": sum(run.row_count for run in result.runs),
                "warnings": [warning for run in result.runs for warning in run.warnings],
            },
            indent=2,
        )
    )
    if report.status in {"FAILED", "UNAVAILABLE"}:
        raise SystemExit(1)


def print_report(value, output=None):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    text = json.dumps(value, indent=2, ensure_ascii=False)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as stream:
            stream.write(text + "\n")
    print(text)


def context_args(args):
    return ArtifactContext(
        acquisition_id=args.acquisition_id,
        extracted_at=args.extracted_at,
        hostname=args.hostname,
        tool_version=args.tool_version,
        volume_id=args.volume_id,
        timezone=args.timezone,
        mount_point=args.mount_point,
        logical_path=args.logical_path,
        recovered_directory=args.recovered_directory,
    )


def run_artifact(args):
    repository = SQLiteRepository(args.db)
    report = ImportService(repository).import_evidence(
        args.case_id,
        args.kind,
        ImportRequest(path=str(args.input), format=args.format, context=context_args(args)),
    )
    print_report(report)
    if report.status in {"FAILED", "UNAVAILABLE"}:
        raise SystemExit(1)


def run_case_import(args):
    repository = SQLiteRepository(args.db)
    case = (
        repository.get_case(args.case_id)
        if args.case_id
        else repository.create_case(CaseCreate(name=args.name))
    )
    context = context_args(args) if args.acquisition_id and args.extracted_at else None
    reports = ImportService(repository).import_case(case.case_id, args.input, context)
    print_report({"case_id": case.case_id, "imports": [report.model_dump(mode="json") for report in reports]})
    if any(report.status in {"FAILED", "UNAVAILABLE"} for report in reports):
        raise SystemExit(1)


def run_view(args):
    service = AnalysisService(SQLiteRepository(args.db))
    if args.command == "correlate":
        result = service.analyze(
            args.case_id, AnalysisRequest(root_event_id=args.root, min_score=args.min_score)
        )
    else:
        result = getattr(service, args.command)(args.case_id, args.root)
        if args.command == "timeline":
            result.events = [
                event
                for event in result.events
                if (args.source is None or event.source == args.source)
                and (args.category is None or getattr(event, args.category, None))
            ]
    print_report(result, args.output)


def add_context(parser, required=True):
    parser.add_argument("--acquisition-id", required=required)
    parser.add_argument("--extracted-at", required=required)
    for name in (
        "hostname",
        "tool-version",
        "volume-id",
        "timezone",
        "mount-point",
        "logical-path",
        "recovered-directory",
    ):
        parser.add_argument("--" + name)


def main():
    # Windows runners/consoles may default to a legacy code page that cannot
    # represent forensic Unicode data such as arrows or non-ASCII paths.
    # EvidenceMesh CLI output is always UTF-8.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="EvidenceMesh forensic correlation tools")
    commands = parser.add_subparsers(dest="command", required=True)
    sample = commands.add_parser("sample", help="Run the synthetic cross-source investigation")
    sample.add_argument("--db", default="data/evidencemesh.sqlite3")
    sample.add_argument("--samples", type=Path, default=DEFAULT_SAMPLE_DIR)
    sample.add_argument("--root", default="MEM-PS")
    sample.add_argument("--output", type=Path)
    sample.set_defaults(run=run_sample)
    memory = commands.add_parser(
        "import-memory", help="Import Volatility 3 JSON exports (no Volatility execution)"
    )
    memory.add_argument("input", type=Path, help="Export folder or single JSON file")
    memory.add_argument("--plugin", help="Required for a file, e.g. windows.pslist or windows.pslist.PsList")
    memory.add_argument(
        "--image-id", required=True, help="Stable unique identifier of the captured memory image"
    )
    memory.add_argument("--extracted-at", required=True, help="Timezone-aware extraction timestamp")
    memory.add_argument("--hostname")
    memory.add_argument("--volatility-version", help="Version used for extraction; unknown if omitted")
    memory.add_argument("--recovered-directory", help="Read-only dumpfiles output directory")
    memory.add_argument("--db", default="data/evidencemesh.sqlite3")
    memory.add_argument("--case-id", help="Append to an existing case; duplicate IDs fail atomically")
    memory.add_argument("--name", default="Volatility Memory Investigation")
    memory.add_argument(
        "--output", type=Path, help="Also write a normalized Event JSON array (exclusive create)"
    )
    memory.set_defaults(run=run_import)
    case = commands.add_parser("case-create", help="Create a case with any subset of evidence sources")
    case.add_argument("--db", default="data/evidencemesh.sqlite3")
    case.add_argument("--name", required=True)
    case.set_defaults(
        run=lambda args: print_report(SQLiteRepository(args.db).create_case(CaseCreate(name=args.name)))
    )
    imports = commands.add_parser("import", help="Import a Memory, Disk or PCAP artifact")
    imports.add_argument(
        "kind", choices=["memory", "mft", "usn", "prefetch", "evtx", "amcache", "file", "pcap"]
    )
    imports.add_argument("input", type=Path)
    imports.add_argument("--format", help="Plugin name for one memory JSON export")
    imports.add_argument("--db", default="data/evidencemesh.sqlite3")
    imports.add_argument("--case-id", required=True)
    add_context(imports)
    imports.set_defaults(run=run_artifact)
    case_import = commands.add_parser(
        "import-case", help="Import case.json or a structured evidence directory"
    )
    case_import.add_argument("input", type=Path)
    case_import.add_argument("--db", default="data/evidencemesh.sqlite3")
    case_import.add_argument("--case-id")
    case_import.add_argument("--name", default="Cross-source Investigation")
    add_context(case_import, required=False)
    case_import.set_defaults(run=run_case_import)
    for name in ("correlate", "timeline", "graph", "parser-runs"):
        view = commands.add_parser(name)
        view.add_argument("--db", default="data/evidencemesh.sqlite3")
        view.add_argument("--case-id", required=True)
        view.add_argument("--root")
        view.add_argument("--output", type=Path)
        if name == "correlate":
            view.add_argument("--min-score", type=int, default=50)
        if name == "timeline":
            view.add_argument("--source", choices=["memory", "disk", "network"])
            view.add_argument("--category", choices=["process", "file", "registry", "network", "service"])
        if name == "parser-runs":
            view.set_defaults(
                run=lambda args: print_report(
                    [
                        run.model_dump(mode="json")
                        for run in SQLiteRepository(args.db).parser_runs(args.case_id)
                    ],
                    args.output,
                )
            )
        else:
            view.set_defaults(run=run_view)
    discovery = commands.add_parser("discover-plugins")
    discovery.add_argument("--executable")
    discovery.set_defaults(run=lambda args: print_report(discover_plugins(args.executable)))
    args = parser.parse_args()
    try:
        args.run(args)
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
