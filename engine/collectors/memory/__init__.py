from engine.collectors.base import ArtifactCollector
from schemas.events import Source


class MemoryCollector(ArtifactCollector):
    def __init__(self):
        super().__init__(Source.MEMORY)
