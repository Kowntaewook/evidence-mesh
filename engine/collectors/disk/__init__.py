from engine.collectors.base import ArtifactCollector
from schemas.events import Source


class DiskCollector(ArtifactCollector):
    def __init__(self):
        super().__init__(Source.DISK)
