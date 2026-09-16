from collections.abc import Iterable
from pathlib import Path
from typing import Any, Protocol


class Parser(Protocol):
    name: str
    version: str

    def parse(self, artifact: Path) -> Iterable[dict[str, Any]]: ...


class UnsupportedParser:
    name = "unsupported"
    version = "0.0.0"

    def parse(self, artifact: Path) -> Iterable[dict[str, Any]]:
        raise NotImplementedError(
            f"{self.name} is a v0.1 stub; export normalized JSON instead: {artifact.name}"
        )


class ArtifactParser:
    """Configured Parser facade. Missing acquisition context never invents provenance."""

    name = "artifact"
    version = "0.3.0"
    kind = ""

    def __init__(self, context=None):
        self.context = context

    def parse(self, artifact: Path) -> list[dict]:
        if self.context is None:
            raise NotImplementedError(f"{self.name}: unconfigured legacy stub; supply ArtifactContext")
        if self.kind == "pcap":
            from engine.collectors.network.pcap import PcapAdapter

            batch = PcapAdapter(self.context).load_file(artifact)
        else:
            from engine.collectors.disk.artifacts import DiskArtifactAdapter

            batch = DiskArtifactAdapter(self.context).load_file(artifact, self.kind)
        if any(run.status != "SUCCESS" for run in batch.runs):
            raise ValueError("; ".join(run.error or run.status for run in batch.runs))
        return [event.model_dump(mode="json") for event in batch.events]
