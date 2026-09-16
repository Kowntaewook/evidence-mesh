import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from engine.collectors.network.pcap import PcapAdapter
from engine.memory_jobs import TERMINAL, MemoryJobs
from engine.runtime import resolve_tshark
from engine.storage import SQLiteRepository
from schemas.imports import ArtifactContext
from schemas.jobs import MemoryJobRequest
from schemas.results import CaseCreate

ROOT = Path(__file__).parents[1]
CONTEXT = ArtifactContext(
    acquisition_id="raw-image-01", extracted_at="2026-09-16T09:35:00Z", hostname="workstation-01"
)


def wait_job(manager, case_id, job_id):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = manager.get(case_id, job_id)
        if result["status"] in TERMINAL:
            return result
        time.sleep(0.02)
    raise AssertionError("Memory job failed to terminate")


@pytest.fixture
def raw_environment(tmp_path):
    image = tmp_path / "image $(literal); 'quoted'.raw"
    image.write_bytes(b"synthetic image container; never claimed as a Windows image")
    worker = tmp_path / "vol worker.py"
    calls = tmp_path / "calls.txt"
    fixtures = ROOT / "tests/fixtures/volatility"
    worker.write_text(
        "import json,sys,time,os\nfrom pathlib import Path\n"
        "if '--help' in sys.argv:\n"
        " print('Volatility 3 Framework 2.28.0\\nwindows.pslist.PsList "
        "windows.cmdline.CmdLine windows.netscan.NetScan')\n"
        " sys.exit(0)\n"
        f"with Path({str(calls)!r}).open('a') as f: f.write(json.dumps(sys.argv)+'\\n')\n"
        "plugin=sys.argv[-1]\n"
        "if plugin=='windows.netscan.NetScan':\n"
        " print('synthetic plugin failure',file=sys.stderr); sys.exit(2)\n"
        "if plugin=='windows.cmdline.CmdLine': time.sleep(30)\n"
        f"print(Path({str(fixtures / 'pslist.json')!r}).read_text())\n"
    )
    repository = SQLiteRepository(tmp_path / "db.sqlite3")
    case = repository.create_case(CaseCreate(name="Raw orchestration"))
    manager = MemoryJobs(repository, tmp_path / "workspace", [sys.executable, str(worker)])
    try:
        yield image, repository, case, manager, calls
    finally:
        manager.close()


def test_raw_execution_partial_failure_unavailable_and_original_lineage(raw_environment):
    image, repository, case, manager, calls = raw_environment
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    job = manager.start(
        case.case_id,
        MemoryJobRequest(
            path=str(image), context=CONTEXT, plugins=["windows.pslist", "windows.netscan", "windows.psscan"]
        ),
    )
    result = wait_job(manager, case.case_id, job["job_id"])
    assert result["status"] == "PARTIAL", result
    assert [p["status"] for p in result["plugins"]] == ["SUCCESS", "FAILED", "UNAVAILABLE"]
    assert result["completed"] == 3
    events = repository.events(case.case_id)
    assert events and all(
        any(
            p.source_artifact.kind == "memory_image" and p.source_artifact.sha256 == before
            for p in event.provenance
        )
        for event in events
    )
    assert hashlib.sha256(image.read_bytes()).hexdigest() == before
    arguments = json.loads(calls.read_text().splitlines()[0])
    assert str(image) in arguments and arguments[-1] == "windows.pslist.PsList"
    assert "-f" in arguments and "-r" in arguments and "--cache-path" in arguments
    runs = repository.parser_runs(case.case_id)
    assert runs[1].exit_code == 2 and "synthetic plugin failure" in runs[1].stderr


def test_raw_cache_hashes_and_explicit_rerun_preserve_prior_exports(raw_environment):
    image, repository, case, manager, calls = raw_environment
    request = MemoryJobRequest(path=str(image), context=CONTEXT, plugins=["windows.pslist"])
    first = wait_job(manager, case.case_id, manager.start(case.case_id, request)["job_id"])
    assert first["status"] == "SUCCESS", first
    original_paths = {
        p.source_artifact.path
        for e in repository.events(case.case_id)
        for p in e.provenance
        if p.source_artifact.kind == "volatility_json"
    }
    second = wait_job(manager, case.case_id, manager.start(case.case_id, request)["job_id"])
    assert second["status"] == "SUCCESS" and second["plugins"][0]["cached"]
    assert len(calls.read_text().splitlines()) == 1
    third = wait_job(
        manager,
        case.case_id,
        manager.start(case.case_id, request.model_copy(update={"rerun": True}))["job_id"],
    )
    assert third["status"] == "SUCCESS" and not third["plugins"][0]["cached"]
    assert len(calls.read_text().splitlines()) == 2
    assert all(Path(path).is_file() for path in original_paths)


def test_raw_timeout_continues_next_plugin(raw_environment):
    image, _, case, manager, _ = raw_environment
    request = MemoryJobRequest(
        path=str(image), context=CONTEXT, timeout_seconds=0.15, plugins=["windows.cmdline", "windows.pslist"]
    )
    result = wait_job(manager, case.case_id, manager.start(case.case_id, request)["job_id"])
    assert result["status"] == "PARTIAL", result
    assert [p["status"] for p in result["plugins"]] == ["TIMEOUT", "SUCCESS"]


def test_raw_cancel_stops_running_plugin(raw_environment):
    image, repository, case, manager, calls = raw_environment
    job = manager.start(
        case.case_id,
        MemoryJobRequest(path=str(image), context=CONTEXT, plugins=["windows.cmdline", "windows.pslist"]),
    )
    deadline = time.monotonic() + 10
    while not calls.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert calls.exists()
    manager.cancel(case.case_id, job["job_id"])
    result = wait_job(manager, case.case_id, job["job_id"])
    assert result["status"] == "CANCELLED"
    assert all(p["status"] == "CANCELLED" for p in result["plugins"])
    assert not repository.events(case.case_id)


def test_raw_identification_and_dumpfiles_require_explicit_selection(raw_environment):
    image, _, case, manager, _ = raw_environment
    with pytest.raises(ValueError, match="FILE_OBJECT"):
        manager.start(
            case.case_id, MemoryJobRequest(path=str(image), context=CONTEXT, plugins=["windows.dumpfiles"])
        )
    with pytest.raises(ValueError, match="memory image"):
        manager.start(case.case_id, MemoryJobRequest(path=str(image.with_suffix(".txt")), context=CONTEXT))
    assert len(MemoryJobRequest(path=str(image), context=CONTEXT).plugins) == 20


def test_tshark_bundled_then_system_then_unavailable(tmp_path, monkeypatch):
    bundled = tmp_path / "tshark.exe"
    bundled.write_bytes(b"discovery only")
    monkeypatch.setenv("EVIDENCEMESH_TSHARK", str(bundled))
    assert resolve_tshark(system=lambda _: "/system/tshark") == str(bundled)
    bundled.unlink()
    assert resolve_tshark(system=lambda _: "/system/tshark") == "/system/tshark"
    assert resolve_tshark(system=lambda _: None) is None


@pytest.mark.parametrize("suffix", ["pcap", "pcapng"])
def test_explicit_bundled_decoder_with_empty_path(tmp_path, monkeypatch, suffix):
    executable = shutil.which("tshark")
    if not executable:
        pytest.skip("Actual tshark runtime required")
    monkeypatch.setenv("EVIDENCEMESH_TSHARK", executable)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert shutil.which("tshark") is None
    batch = PcapAdapter(CONTEXT).load_file(ROOT / "tests/fixtures/network" / ("sample." + suffix))
    assert batch.runs[0].status == "SUCCESS", batch.runs[0].error
    assert {"dns_response", "network_flow", "http_request", "tls_client_hello"} <= {
        e.type for e in batch.events
    }
    assert batch.runs[0].command[0] == executable


def test_launcher_dynamic_health_sqlite_auth_and_parent_shutdown(tmp_path):
    env = {
        **os.environ,
        "EVIDENCEMESH_WORKSPACE": str(tmp_path),
        "EVIDENCEMESH_SESSION_TOKEN": "test-session",
        "EVIDENCEMESH_INSTANCE": "test-instance",
    }
    env.pop("EVIDENCEMESH_DB", None)
    process = subprocess.Popen(
        [sys.executable, "-m", "api.launcher", "--parent-pipe"],
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        with ThreadPoolExecutor(1) as pool:
            address = json.loads(pool.submit(process.stdout.readline).result(timeout=15))
        assert address["host"] == "127.0.0.1" and address["port"] > 0
        url = "http://127.0.0.1:" + str(address["port"]) + "/health"
        deadline = time.monotonic() + 15
        while True:
            try:
                with urlopen(
                    Request(url, headers={"X-EvidenceMesh-Token": "test-session"}), timeout=1
                ) as response:
                    data = json.load(response)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        assert data == {"status": "ok", "version": "0.4.0", "instance": "test-instance"}
        assert (tmp_path / "evidencemesh.sqlite3").exists()
        with pytest.raises(HTTPError) as error:
            urlopen(url, timeout=2)
        assert error.value.code == 401
        process.stdin.close()
        assert process.wait(timeout=10) == 0
        assert "backend shutdown" in (tmp_path / "logs/backend.log").read_text()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_launcher_occupied_explicit_port_fails(tmp_path):
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        result = subprocess.run(
            [sys.executable, "-m", "api.launcher", "--port", str(occupied.getsockname()[1])],
            cwd=ROOT,
            env={**os.environ, "EVIDENCEMESH_WORKSPACE": str(tmp_path)},
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode != 0 and "backend-address" not in result.stdout
