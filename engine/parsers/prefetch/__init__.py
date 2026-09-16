from engine.parsers.base import ArtifactParser


class PrefetchParser(ArtifactParser):
    """Prefetch SCCA/export facade; compressed MAM is explicitly unavailable."""

    name = "windows-prefetch"
    kind = "prefetch"
