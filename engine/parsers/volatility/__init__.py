from pathlib import Path

from engine.parsers.volatility.rows import ImportContext, VolatilityImportError


class VolatilityParser:
    """Configured single-export Parser protocol facade; use Adapter for multi-plugin merging."""

    name = "volatility3"
    version = "0.2.0"

    def __init__(self, plugin: str | None = None, context: ImportContext | None = None):
        self.plugin, self.context = plugin, context

    def parse(self, artifact: Path) -> list[dict]:
        if self.plugin is None:
            raise NotImplementedError("Automatic plugin detection is a stub; supply plugin and ImportContext")
        if self.context is None:
            raise VolatilityImportError(
                "ImportContext with image identifier and extraction timestamp is required"
            )
        from engine.collectors.memory.volatility import Volatility3Adapter

        return [
            event.model_dump(mode="json")
            for event in Volatility3Adapter(self.context).load_file(artifact, self.plugin).events
        ]
