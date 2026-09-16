from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from engine.normalization import normalize_event
from engine.sample import load_sample


@pytest.fixture
def make_event():
    def make(event_id="A", **overrides):
        record = {
            "event_id": event_id,
            "timestamp": "2026-09-16T09:31:25Z",
            "source": "memory",
            "type": "observation",
            "hostname": "host-01",
        }
        record.update(deepcopy(overrides))
        return normalize_event(record)

    return make


@pytest.fixture
def sample():
    return load_sample()


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path / "test.sqlite3")) as client:
        yield client
