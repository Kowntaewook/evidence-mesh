from engine.collectors.base import ArtifactCollector
from schemas.events import Source


class NetworkCollector(ArtifactCollector):
    def __init__(self):
        super().__init__(Source.NETWORK)
