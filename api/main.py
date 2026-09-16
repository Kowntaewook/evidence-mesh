import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import Field

from engine.ingestion.service import ImportService
from engine.normalization import normalize_events
from engine.parsers.volatility.registry import discover_plugins
from engine.sample import DEFAULT_SAMPLE_DIR, load_sample
from engine.service import AnalysisService
from engine.storage import SQLiteRepository
from engine.storage.base import AnalysisRequiredError, ConflictError, NotFoundError
from schemas.events import Event, Source, Timestamp
from schemas.imports import ImportReport, ImportRequest, ParserRun
from schemas.results import (
    AnalysisRequest,
    AnalysisResult,
    Case,
    CaseCreate,
    Correlation,
    IncidentGraph,
    Timeline,
)


def create_app(database_path: str | Path | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.repository = SQLiteRepository(
            database_path or os.environ.get("EVIDENCEMESH_DB", "data/evidencemesh.sqlite3")
        )
        yield

    app = FastAPI(
        title="EvidenceMesh",
        version="0.3.0",
        lifespan=lifespan,
        description="Cross-source forensic correlation engine for memory, disk, and network evidence.",
    )

    @app.exception_handler(NotFoundError)
    async def not_found(request, exc):
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ConflictError)
    @app.exception_handler(AnalysisRequiredError)
    async def conflict(request, exc):
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.get("/health")
    def health(request: Request):
        with request.app.state.repository.connection() as db:
            db.execute("SELECT 1").fetchone()
        return {"status": "ok", "version": "0.3.0"}

    @app.post("/cases", response_model=Case, status_code=201)
    def create_case(body: CaseCreate, request: Request):
        return request.app.state.repository.create_case(body)

    @app.get("/cases", response_model=list[Case])
    def cases(request: Request):
        return request.app.state.repository.list_cases()

    @app.post("/samples/load", response_model=Case, status_code=201)
    def sample(request: Request):
        path = Path(os.environ.get("EVIDENCEMESH_SAMPLE_DIR", str(DEFAULT_SAMPLE_DIR)))
        try:
            events = load_sample(path)
        except OSError as exc:
            raise HTTPException(
                status_code=503, detail="Sample files unavailable; set EVIDENCEMESH_SAMPLE_DIR"
            ) from exc
        repository = request.app.state.repository
        case = repository.create_case(
            CaseCreate(
                name="Sample Investigation", description="Synthetic evidence; no live traffic or malware"
            )
        )
        repository.add_events(case.case_id, events)
        return repository.get_case(case.case_id)

    @app.get("/cases/{case_id}", response_model=Case)
    def get_case(case_id: str, request: Request):
        return request.app.state.repository.get_case(case_id)

    @app.post("/cases/{case_id}/events", status_code=201)
    def add_events(
        case_id: str, body: Annotated[list[Event], Field(min_length=1, max_length=5000)], request: Request
    ):
        count = request.app.state.repository.add_events(case_id, normalize_events(body))
        return {"imported": count, "analysis_required": True}

    @app.get("/cases/{case_id}/events", response_model=list[Event])
    def events(
        case_id: str,
        request: Request,
        source: Source | None = None,
        pid: int | None = None,
        event_type: str | None = None,
        artifact_type: str | None = None,
        limit: Annotated[int | None, Query(ge=1, le=5000)] = None,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        return request.app.state.repository.query_events(
            case_id,
            source=source,
            pid=pid,
            event_type=event_type,
            artifact_type=artifact_type,
            limit=limit,
            offset=offset,
        )

    @app.post("/cases/{case_id}/import/{kind}", response_model=ImportReport)
    def import_evidence(case_id: str, kind: str, body: ImportRequest, request: Request):
        if kind not in {
            "memory",
            "disk",
            "network",
            "mft",
            "usn",
            "prefetch",
            "evtx",
            "amcache",
            "pcap",
            "file",
        }:
            raise HTTPException(422, "Unsupported evidence kind")
        return ImportService(request.app.state.repository).import_evidence(case_id, kind, body)

    @app.get("/parsers/volatility")
    def plugins():
        return discover_plugins()

    @app.get("/cases/{case_id}/parser-runs", response_model=list[ParserRun])
    def parser_runs(case_id: str, request: Request):
        return request.app.state.repository.parser_runs(case_id)

    @app.get("/cases/{case_id}/imports", response_model=list[ImportReport])
    def imports(case_id: str, request: Request):
        return request.app.state.repository.imports(case_id)

    @app.get("/cases/{case_id}/processes", response_model=list[Event])
    def processes(
        case_id: str,
        request: Request,
        limit: Annotated[int, Query(ge=1, le=5000)] = 500,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        return request.app.state.repository.query_events(
            case_id, category="process", limit=limit, offset=offset
        )

    @app.get("/cases/{case_id}/files", response_model=list[Event])
    def files(
        case_id: str,
        request: Request,
        limit: Annotated[int, Query(ge=1, le=5000)] = 500,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        return request.app.state.repository.query_events(case_id, category="file", limit=limit, offset=offset)

    @app.get("/cases/{case_id}/network", response_model=list[Event])
    def network(
        case_id: str,
        request: Request,
        limit: Annotated[int, Query(ge=1, le=5000)] = 500,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        return request.app.state.repository.query_events(
            case_id, category="network", limit=limit, offset=offset
        )

    @app.post("/cases/{case_id}/correlate", response_model=AnalysisResult)
    def correlate(case_id: str, request: Request, body: AnalysisRequest | None = None):
        return AnalysisService(request.app.state.repository).analyze(case_id, body or AnalysisRequest())

    @app.get("/cases/{case_id}/correlations", response_model=list[Correlation])
    def correlations(case_id: str, request: Request, root_event_id: Annotated[str | None, Query()] = None):
        return AnalysisService(request.app.state.repository).view(case_id, root_event_id)[1]

    @app.get("/cases/{case_id}/graph", response_model=IncidentGraph)
    def graph(case_id: str, request: Request, root_event_id: str | None = None):
        return AnalysisService(request.app.state.repository).graph(case_id, root_event_id)

    @app.get("/cases/{case_id}/timeline", response_model=Timeline)
    def timeline(
        case_id: str,
        request: Request,
        root_event_id: str | None = None,
        source: Source | None = None,
        category: Literal["process", "file", "network", "registry", "service", "dns", "connection"]
        | None = None,
        pid: int | None = None,
        start: Timestamp | None = None,
        end: Timestamp | None = None,
        limit: Annotated[int | None, Query(ge=1, le=5000)] = None,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        if start and end and start > end:
            raise ValueError("Timeline start must not follow end")
        if not root_event_id:
            return Timeline(
                events=request.app.state.repository.query_events(
                    case_id,
                    source=source,
                    category=category,
                    pid=pid,
                    start=start,
                    end=end,
                    limit=limit,
                    offset=offset,
                )
            )
        result = AnalysisService(request.app.state.repository).timeline(case_id, root_event_id)
        result.events = [
            event
            for event in result.events
            if (source is None or event.source == source)
            and (
                category is None
                or (
                    bool(event.network and event.network.dns_query)
                    if category == "dns"
                    else bool(event.network and not event.network.dns_query)
                    if category == "connection"
                    else getattr(event, category, None)
                )
            )
            and (pid is None or event.process and event.process.pid == pid)
            and (start is None or event.timestamp >= start)
            and (end is None or event.timestamp <= end)
        ]
        result.events = result.events[offset : offset + limit if limit else None]
        return result

    return app


app = create_app()
