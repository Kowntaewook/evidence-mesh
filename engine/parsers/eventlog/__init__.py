from engine.parsers.base import ArtifactParser


class EventLogParser(ArtifactParser):
    """EVTX binary, Event XML and documented export facade."""

    name = "windows-eventlog"
    kind = "evtx"
