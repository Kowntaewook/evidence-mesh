from engine.parsers.base import ArtifactParser


class MFTParser(ArtifactParser):
    """Read-only MFT binary/export facade; acquisition context is required."""

    name = "ntfs-mft"
    kind = "mft"


class USNParser(ArtifactParser):
    """Read-only USN v2/export facade."""

    name = "ntfs-usn"
    kind = "usn"
