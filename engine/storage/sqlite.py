import sqlite3
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from engine.normalization.windows import path_key
from schemas.events import Event
from schemas.imports import ImportBatch, ImportReport
from schemas.results import Case, CaseCreate, Correlation

from .base import AnalysisRequiredError, ConflictError, NotFoundError


class SQLiteRepository:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path == ":memory:":
            raise ValueError("Use a temporary SQLite file; repository connections are scoped to operations")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 3):
                raise ValueError(f"Unsupported database schema version: {version}")
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
                    created_at TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0, analysis_revision INTEGER
                );
                CREATE TABLE IF NOT EXISTS events (
                    case_id TEXT NOT NULL REFERENCES cases(case_id), event_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL, source TEXT NOT NULL, data TEXT NOT NULL,
                    PRIMARY KEY(case_id, event_id)
                );
                CREATE INDEX IF NOT EXISTS events_time ON events(case_id, timestamp);
                CREATE TABLE IF NOT EXISTS correlations (
                    case_id TEXT NOT NULL, source_event TEXT NOT NULL, target_event TEXT NOT NULL,
                    data TEXT NOT NULL, PRIMARY KEY(case_id, source_event, target_event),
                    FOREIGN KEY(case_id, source_event) REFERENCES events(case_id, event_id),
                    FOREIGN KEY(case_id, target_event) REFERENCES events(case_id, event_id)
                );
            """)
            self._migrate(db)

    @staticmethod
    def _migrate(db):
        columns = {row[1] for row in db.execute("PRAGMA table_info(events)")}
        fields = {
            "pid": "INTEGER",
            "event_type": "TEXT",
            "sha256": "TEXT",
            "ip": "TEXT",
            "domain": "TEXT",
            "normalized_path": "TEXT",
            "artifact_type": "TEXT",
        }
        for name, kind in fields.items():
            if name not in columns:
                db.execute(f"ALTER TABLE events ADD COLUMN {name} {kind}")
        if "event_type" not in columns:
            for row in db.execute("SELECT case_id,event_id,data FROM events").fetchall():
                event = Event.model_validate_json(row[2])
                db.execute(
                    "UPDATE events SET pid=?,event_type=?,sha256=?,ip=?,domain=?,normalized_path=?,"
                    "artifact_type=? WHERE case_id=? AND event_id=?",
                    (*SQLiteRepository._indexed(event), row[0], row[1]),
                )
        for field in ["source", *fields]:
            db.execute(f"CREATE INDEX IF NOT EXISTS events_{field} ON events(case_id,{field})")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS evidence_sources (
                case_id TEXT NOT NULL REFERENCES cases(case_id), artifact_id TEXT NOT NULL,
                path TEXT NOT NULL, sha256 TEXT, size INTEGER, imported_at TEXT, data TEXT NOT NULL,
                PRIMARY KEY(case_id,artifact_id,path)
            );
            CREATE TABLE IF NOT EXISTS imports (
                import_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(case_id),
                status TEXT NOT NULL, event_count INTEGER NOT NULL, data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS imports_case ON imports(case_id);
            CREATE TABLE IF NOT EXISTS parser_runs (
                run_id TEXT PRIMARY KEY, import_id TEXT NOT NULL REFERENCES imports(import_id),
                case_id TEXT NOT NULL REFERENCES cases(case_id), parser TEXT NOT NULL,
                status TEXT NOT NULL, data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS parser_runs_case ON parser_runs(case_id);
            CREATE INDEX IF NOT EXISTS correlations_target ON correlations(case_id,target_event);
            CREATE TABLE IF NOT EXISTS correlation_reasons (
                case_id TEXT NOT NULL, source_event TEXT NOT NULL, target_event TEXT NOT NULL,
                ordinal INTEGER NOT NULL, rule TEXT NOT NULL, score INTEGER NOT NULL, data TEXT NOT NULL,
                PRIMARY KEY(case_id,source_event,target_event,ordinal),
                FOREIGN KEY(case_id,source_event,target_event)
                  REFERENCES correlations(case_id,source_event,target_event) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS entities (
                case_id TEXT NOT NULL REFERENCES cases(case_id), entity_id TEXT NOT NULL,
                kind TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(case_id,entity_id)
            );
            CREATE TABLE IF NOT EXISTS graph_nodes (
                case_id TEXT NOT NULL REFERENCES cases(case_id), node_id TEXT NOT NULL,
                data TEXT NOT NULL, PRIMARY KEY(case_id,node_id)
            );
            CREATE TABLE IF NOT EXISTS graph_edges (
                case_id TEXT NOT NULL REFERENCES cases(case_id), edge_id TEXT NOT NULL,
                source_node TEXT NOT NULL, target_node TEXT NOT NULL, data TEXT NOT NULL,
                PRIMARY KEY(case_id,edge_id)
            );
            PRAGMA user_version=3;
        """)

    @staticmethod
    def _indexed(event):
        return (
            event.process.pid if event.process else None,
            event.type,
            (event.file.sha256 if event.file else None) or (event.hash.sha256 if event.hash else None),
            event.network.dst_ip if event.network else None,
            event.network.dns_query or (event.network.tls.sni if event.network.tls else None)
            if event.network
            else None,
            path_key(event.file.path) if event.file and event.file.path else None,
            event.artifact_type,
        )

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _case(db, case_id: str) -> Case:
        row = db.execute(
            """SELECT c.*, (SELECT COUNT(*) FROM events e WHERE e.case_id=c.case_id) event_count
                            FROM cases c WHERE c.case_id=?""",
            (case_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"Case not found: {case_id}")
        return Case.model_validate(dict(row))

    def create_case(self, request: CaseCreate) -> Case:
        case = Case(case_id=str(uuid4()), **request.model_dump())
        with self.connection() as db:
            db.execute(
                "INSERT INTO cases(case_id,name,description,created_at) VALUES (?,?,?,?)",
                (case.case_id, case.name, case.description, case.created_at.isoformat()),
            )
        return case

    def get_case(self, case_id: str) -> Case:
        with self.connection() as db:
            return self._case(db, case_id)

    def list_cases(self) -> list[Case]:
        with self.connection() as db:
            return [
                self._case(db, row[0])
                for row in db.execute("SELECT case_id FROM cases ORDER BY created_at,case_id")
            ]

    def add_events(self, case_id: str, events: list[Event], report: ImportReport | None = None) -> int:
        if not events and not report:
            raise ValueError("Cannot import an empty event batch")
        try:
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                self._case(db, case_id)
                db.executemany(
                    "INSERT INTO events(case_id,event_id,timestamp,source,data,pid,event_type,sha256,"
                    "ip,domain,"
                    "normalized_path,artifact_type) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            case_id,
                            e.event_id,
                            e.timestamp.isoformat(),
                            e.source.value,
                            e.model_dump_json(),
                            *self._indexed(e),
                        )
                        for e in events
                    ],
                )
                artifacts = [e.source_artifact for e in events if e.source_artifact]
                artifacts.extend(p.source_artifact for e in events for p in e.provenance)
                if report:
                    artifacts.extend(run.artifact for run in report.runs if run.artifact)
                    self._record_import(db, report)
                unique = {(a.artifact_id, a.path): a for a in artifacts}
                db.executemany(
                    "INSERT OR IGNORE INTO evidence_sources VALUES (?,?,?,?,?,?,?)",
                    [
                        (
                            case_id,
                            a.artifact_id,
                            a.path or "",
                            a.sha256,
                            a.size,
                            a.imported_at.isoformat() if a.imported_at else None,
                            a.model_dump_json(),
                        )
                        for a in unique.values()
                    ],
                )
                if events:
                    for table in ("correlations", "entities", "graph_nodes", "graph_edges"):
                        db.execute(f"DELETE FROM {table} WHERE case_id=?", (case_id,))
                    db.execute(
                        "UPDATE cases SET revision=revision+1, analysis_revision=NULL WHERE case_id=?",
                        (case_id,),
                    )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("Duplicate event ID; entire import rolled back") from exc
        return len(events)

    @staticmethod
    def _record_import(db, report):
        db.execute(
            "INSERT INTO imports VALUES (?,?,?,?,?)",
            (report.import_id, report.case_id, report.status, report.imported, report.model_dump_json()),
        )
        db.executemany(
            "INSERT INTO parser_runs VALUES (?,?,?,?,?,?)",
            [
                (run.run_id, report.import_id, report.case_id, run.parser, run.status, run.model_dump_json())
                for run in report.runs
            ],
        )

    def import_batch(self, case_id: str, batch: ImportBatch) -> ImportReport:
        from schemas.imports import RunStatus

        states = {run.status for run in batch.runs}
        status = (
            "SUCCESS"
            if states == {RunStatus.SUCCESS}
            else (
                "PARTIAL"
                if batch.events
                else "FAILED"
                if states & {RunStatus.FAILED, RunStatus.TIMEOUT}
                else "CANCELLED"
                if RunStatus.CANCELLED in states
                else "UNAVAILABLE"
            )
        )
        report = ImportReport(
            import_id=str(uuid4()),
            case_id=case_id,
            imported=len(batch.events),
            status=status,
            runs=batch.runs,
        )
        for run in report.runs:
            run.import_id = report.import_id
        try:
            self.add_events(case_id, batch.events, report)
        except (ConflictError, sqlite3.Error) as exc:
            report.status, report.imported = "FAILED", 0
            for run in report.runs:
                if run.status == RunStatus.SUCCESS:
                    run.status, run.event_count, run.error = RunStatus.FAILED, 0, f"Storage: {exc}"
            with self.connection() as db:
                self._record_import(db, report)
        return report

    def parser_runs(self, case_id):
        from schemas.imports import ParserRun

        with self.connection() as db:
            self._case(db, case_id)
            return [
                ParserRun.model_validate_json(row[0])
                for row in db.execute(
                    "SELECT data FROM parser_runs WHERE case_id=? ORDER BY rowid", (case_id,)
                )
            ]

    def imports(self, case_id):
        with self.connection() as db:
            self._case(db, case_id)
            return [
                ImportReport.model_validate_json(row[0])
                for row in db.execute("SELECT data FROM imports WHERE case_id=? ORDER BY rowid", (case_id,))
            ]

    def query_events(
        self,
        case_id,
        *,
        source=None,
        pid=None,
        event_type=None,
        artifact_type=None,
        category=None,
        start=None,
        end=None,
        limit=None,
        offset=0,
    ):
        clauses, values = ["case_id=?"], [case_id]
        for key, value in (
            ("source", source),
            ("pid", pid),
            ("event_type", event_type),
            ("artifact_type", artifact_type),
        ):
            if value is not None:
                clauses.append(f"{key}=?")
                values.append(value)
        if category in {"process", "file", "network", "registry", "service"}:
            clauses.append(f"json_type(data,'$.{category}')='object'")
        elif category == "dns":
            clauses.append("json_extract(data,'$.network.dns_query') IS NOT NULL")
        elif category == "connection":
            clauses.append(
                "json_type(data,'$.network')='object' AND json_extract(data,'$.network.dns_query') IS NULL"
            )
        for operator, value in ((">=", start), ("<=", end)):
            if value is not None:
                clauses.append(f"timestamp{operator}?")
                values.append(value.isoformat())
        query = "SELECT data FROM events WHERE " + " AND ".join(clauses) + " ORDER BY timestamp,event_id"
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            values.extend([limit, offset])
        elif offset:
            query += " LIMIT -1 OFFSET ?"
            values.append(offset)
        with self.connection() as db:
            self._case(db, case_id)
            return [Event.model_validate_json(row[0]) for row in db.execute(query, values)]

    def save_graph(self, case_id, graph, revision):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if self._case(db, case_id).revision != revision:
                raise ConflictError("Evidence changed while building graph")
            for table in ("entities", "graph_nodes", "graph_edges"):
                db.execute(f"DELETE FROM {table} WHERE case_id=?", (case_id,))
            db.executemany(
                "INSERT INTO graph_nodes VALUES (?,?,?)",
                [(case_id, n.id, n.model_dump_json()) for n in graph.nodes],
            )
            db.executemany(
                "INSERT INTO entities VALUES (?,?,?,?)",
                [(case_id, n.id, n.kind, n.model_dump_json()) for n in graph.nodes if n.kind != "Event"],
            )
            db.executemany(
                "INSERT INTO graph_edges VALUES (?,?,?,?,?)",
                [(case_id, e.id, e.source, e.target, e.model_dump_json()) for e in graph.edges],
            )

    def events(self, case_id: str) -> list[Event]:
        with self.connection() as db:
            self._case(db, case_id)
            values = [
                Event.model_validate_json(row[0])
                for row in db.execute("SELECT data FROM events WHERE case_id=?", (case_id,))
            ]
            return sorted(values, key=lambda event: (event.timestamp, event.event_id))

    def save_correlations(self, case_id: str, correlations: list[Correlation], revision: int) -> None:
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            case = self._case(db, case_id)
            if case.revision != revision:
                raise ConflictError("Evidence changed during analysis; run correlation again")
            db.execute("DELETE FROM correlations WHERE case_id=?", (case_id,))
            db.executemany(
                "INSERT INTO correlations VALUES (?,?,?,?)",
                [
                    (case_id, edge.source_event, edge.target_event, edge.model_dump_json())
                    for edge in correlations
                ],
            )
            db.executemany(
                "INSERT INTO correlation_reasons VALUES (?,?,?,?,?,?,?)",
                [
                    (
                        case_id,
                        edge.source_event,
                        edge.target_event,
                        ordinal,
                        reason.rule,
                        reason.score,
                        reason.model_dump_json(),
                    )
                    for edge in correlations
                    for ordinal, reason in enumerate(edge.reasons)
                ],
            )
            db.execute("UPDATE cases SET analysis_revision=? WHERE case_id=?", (revision, case_id))

    def correlations(self, case_id: str) -> list[Correlation]:
        with self.connection() as db:
            db.execute("BEGIN")
            case = self._case(db, case_id)
            if case.analysis_revision != case.revision:
                raise AnalysisRequiredError("No current analysis; run correlation after importing evidence")
            return [
                Correlation.model_validate_json(row[0])
                for row in db.execute(
                    "SELECT data FROM correlations WHERE case_id=? ORDER BY source_event,target_event",
                    (case_id,),
                )
            ]
