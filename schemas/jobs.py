from pydantic import Field, field_validator

from engine.parsers.volatility.registry import SPECS, canonical_plugin
from schemas.events import Address, Model
from schemas.imports import ArtifactContext


class MemoryJobRequest(Model):
    path: str
    context: ArtifactContext
    plugins: list[str] = Field(
        default_factory=lambda: [s.name for s in SPECS if s.name != "windows.dumpfiles"]
    )
    timeout_seconds: float = Field(default=300, ge=0.1, le=3600)
    rerun: bool = False
    file_objects: list[Address] = Field(default_factory=list, max_length=100)

    @field_validator("plugins")
    @classmethod
    def valid_plugins(cls, values):
        if not values or len(values) > len(SPECS):
            raise ValueError("Select between one and 21 supported plugins")
        return list(dict.fromkeys(canonical_plugin(value) for value in values))
