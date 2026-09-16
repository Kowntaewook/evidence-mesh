"""Runtime discovery shared by development and the self-contained Windows build."""

import importlib
import importlib.metadata
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from engine.version import VERSION


def workspace_root() -> Path:
    if value := os.environ.get("EVIDENCEMESH_WORKSPACE"):
        return Path(value).expanduser().resolve()
    if getattr(sys, "frozen", False):
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / "EvidenceMesh"
    return Path(os.environ.get("EVIDENCEMESH_DB", "data/evidencemesh.sqlite3")).resolve().parent


def configure_logging() -> Path:
    directory = workspace_root() / "logs"
    directory.mkdir(parents=True, exist_ok=True)
    filename = directory / "backend.log"
    logger = logging.getLogger("evidencemesh")
    if not logger.handlers:
        handler = RotatingFileHandler(filename, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return filename


def resolve_tshark(explicit: str | None = None, system=None) -> str | None:
    if explicit:
        return explicit
    if bundled := os.environ.get("EVIDENCEMESH_TSHARK"):
        path = Path(bundled)
        if path.is_absolute() and path.is_file():
            return str(path)
    return (system or shutil.which)("tshark")


def volatility_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--volatility"]
    return [sys.executable, "-m", "api.launcher", "--volatility"]


def dependency_status() -> dict:
    components = {}
    for module, distribution in (
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn"),
        ("tzdata", "tzdata"),
        ("volatility3", "volatility3"),
        ("Evtx", "python-evtx"),
        ("dissect.ntfs", "dissect.ntfs"),
        ("dissect.regf", "dissect.regf"),
        ("dissect.util", "dissect.util"),
        ("samples", None),
        ("schemas", None),
    ):
        try:
            importlib.import_module(module)
            version = importlib.metadata.version(distribution) if distribution else VERSION
            components[module] = {"status": "OK", "version": version}
        except (ImportError, importlib.metadata.PackageNotFoundError) as exc:
            components[module] = {"status": "UNAVAILABLE", "error": str(exc)}
    executable = resolve_tshark()
    tshark = {"status": "UNAVAILABLE", "path": executable, "embedded": False}
    if executable:
        try:
            result = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=15)
            tshark.update(
                status="OK" if result.returncode == 0 else "FAILED",
                version=result.stdout.splitlines()[0] if result.stdout else None,
                embedded=executable == os.environ.get("EVIDENCEMESH_TSHARK"),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            tshark["error"] = str(exc)
    from importlib.resources import files

    data_status = {}
    for package, relative in (
        ("samples", "sample_case/memory_events.json"),
        ("schemas", "event.schema.json"),
    ):
        try:
            json.loads(files(package).joinpath(relative).read_text())
            data_status[package] = "OK"
        except (OSError, ValueError, ModuleNotFoundError) as exc:
            data_status[package] = str(exc)
    return {
        "version": VERSION,
        "backend": {
            "status": "OK",
            "embedded": bool(getattr(sys, "frozen", False)),
            "python": sys.version.split()[0],
        },
        "components": components,
        "data": data_status,
        "tshark": tshark,
        "sqlite": {"status": "OK", "version": sqlite3.sqlite_version},
        "workspace": str(workspace_root()),
    }
