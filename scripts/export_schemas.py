import json
from pathlib import Path

from schemas.events import Event
from schemas.results import Correlation, IncidentGraph


def main():
    target = Path(__file__).resolve().parent.parent / "schemas"
    for name, model in (("event", Event), ("correlation", Correlation), ("graph", IncidentGraph)):
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", **model.model_json_schema()}
        (target / f"{name}.schema.json").write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
