from typing import Literal

from pydantic import Field

from schemas.events import Model
from schemas.imports import ArtifactContext


class DiskImageRequest(Model):
    path: str
    context: ArtifactContext
    artifacts: list[Literal["mft", "usn", "prefetch", "evtx", "amcache"]] = Field(
        default_factory=lambda: ["mft", "usn", "prefetch", "evtx", "amcache"], min_length=1, max_length=5
    )
    volumes: list[str] | None = Field(default=None, min_length=1, max_length=4096)
