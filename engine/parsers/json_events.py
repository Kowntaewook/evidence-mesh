import hashlib
import json
from pathlib import Path

from engine.version import VERSION


class JsonEventParser:
    """Read-only adapter for JSON event arrays, with content-based provenance."""

    name = "evidencemesh-json"
    version = VERSION

    def parse(self, artifact: Path) -> list[dict]:
        payload = artifact.read_bytes()
        records = json.loads(payload)
        if (
            not isinstance(records, list)
            or not records
            or not all(isinstance(item, dict) for item in records)
        ):
            raise ValueError("Evidence JSON must be a nonempty array of event objects")
        digest = hashlib.sha256(payload).hexdigest()
        for index, record in enumerate(records):
            # Imported artifact metadata remains intact. JSON import provenance is additional.
            if record.get("source_artifact") is None and record.get("raw_reference") is None:
                record["source_artifact"] = {
                    "artifact_id": f"sha256:{digest}",
                    "kind": "json_export",
                    "path": str(artifact),
                    "sha256": digest,
                }
                record["raw_reference"] = {
                    "artifact_id": record["source_artifact"]["artifact_id"],
                    "locator": f"/{index}",
                }
            if record.get("parser") is None:
                record["parser"] = {"name": self.name, "version": self.version}
            attributes = record.setdefault("attributes", {})
            if not isinstance(attributes, dict):
                raise ValueError("Event attributes must be a JSON object")
            if "import_reference" in attributes:
                history = attributes.setdefault("import_history", [])
                if not isinstance(history, list):
                    raise ValueError("attributes.import_history must be an array")
                history.append(attributes["import_reference"])
            attributes["import_reference"] = {
                "path": str(artifact),
                "sha256": digest,
                "json_pointer": f"/{index}",
            }
        return records
