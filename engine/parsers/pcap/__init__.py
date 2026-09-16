from engine.parsers.base import ArtifactParser


class PCAPParser(ArtifactParser):
    """Offline tshark PCAP/PCAPNG facade."""

    name = "pcap"
    kind = "pcap"
