from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import ip_address
from typing import Annotated, Literal

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, JsonValue, model_validator


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


def utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


Timestamp = Annotated[AwareDatetime, AfterValidator(utc)]
SHA256 = Annotated[str, Field(pattern=r"^[a-fA-F0-9]{64}$"), AfterValidator(str.lower)]
Identifier = Annotated[str, Field(min_length=1, max_length=256)]
PID = Annotated[int, Field(strict=True, ge=0, le=4294967295)]
Port = Annotated[int, Field(strict=True, ge=0, le=65535)]
NonNegative = Annotated[int, Field(strict=True, ge=0)]
Address = Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]+$")]


class Source(StrEnum):
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"


class Process(Model):
    pid: PID
    ppid: PID | None = None
    name: str | None = None
    path: str | None = None
    command_line: str | None = None
    creation_time: Timestamp | None = None
    instance_id: Identifier | None = None
    parent_instance_id: Identifier | None = None
    exit_time: Timestamp | None = None
    environment: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def valid_lifetime(self):
        if self.creation_time and self.exit_time and self.exit_time < self.creation_time:
            raise ValueError("Process exit_time precedes creation_time")
        return self


class File(Model):
    path: str | None = None
    name: str | None = None
    sha256: SHA256 | None = None
    references: list[str] = Field(default_factory=list)
    size: NonNegative | None = None
    volume_id: str | None = None
    record_number: NonNegative | None = None
    sequence_number: NonNegative | None = None
    parent_record: NonNegative | None = None
    parent_sequence: NonNegative | None = None
    allocated: bool | None = None
    flags: list[str] = Field(default_factory=list)
    si_timestamps: dict[str, Timestamp] = Field(default_factory=dict)
    fn_timestamps: dict[str, Timestamp] = Field(default_factory=dict)
    file_object: Address | None = None


class HTTPInfo(Model):
    method: str | None = None
    host: str | None = None
    uri: str | None = None
    user_agent: str | None = None
    status: Annotated[int, Field(ge=100, le=599)] | None = None
    content_type: str | None = None


class TLSInfo(Model):
    sni: str | None = None
    version: str | None = None
    client_ip: str | None = None
    server_ip: str | None = None
    server_port: Port | None = None

    @model_validator(mode="after")
    def valid_addresses(self):
        for value in (self.client_ip, self.server_ip):
            if value is not None:
                ip_address(value)
        return self


class Network(Model):
    src_ip: str | None = None
    src_port: Port | None = None
    dst_ip: str | None = None
    dst_port: Port | None = None
    protocol: str | None = None
    dns_query: str | None = None
    resolved_ips: list[str] = Field(default_factory=list)
    state: str | None = None
    end_time: Timestamp | None = None
    packet_count: NonNegative | None = None
    byte_count: NonNegative | None = None
    stream_id: str | None = None
    flags: list[str] = Field(default_factory=list)
    dns_query_type: str | None = None
    dns_response: bool | None = None
    dns_id: str | None = None
    http: HTTPInfo | None = None
    tls: TLSInfo | None = None

    @model_validator(mode="after")
    def valid_addresses(self):
        for value in [self.src_ip, self.dst_ip, *self.resolved_ips]:
            if value is not None:
                ip_address(value)
        return self


class User(Model):
    name: str | None = None
    sid: str | None = None
    domain: str | None = None


class Hashes(Model):
    sha256: SHA256 | None = None
    sha1: Annotated[str, Field(pattern=r"^[a-fA-F0-9]{40}$")] | None = None


class SourceArtifact(Model):
    artifact_id: Identifier
    kind: str
    path: str | None = None
    sha256: SHA256 | None = None
    size: NonNegative | None = None
    imported_at: Timestamp | None = None


class ParserInfo(Model):
    name: str
    version: str


class RawReference(Model):
    artifact_id: Identifier
    locator: str = Field(description="JSON pointer, record number, byte offset, or packet number")


class Provenance(Model):
    source_artifact: SourceArtifact
    raw_reference: RawReference
    parser: ParserInfo
    tool: str
    tool_version: str | None = None
    plugin: str | None = None
    memory_image_id: Identifier | None = None
    source: Source | None = None
    acquisition_id: Identifier | None = None
    extraction_timestamp: Timestamp
    row_index: int = Field(ge=0, strict=True)
    raw: dict[str, JsonValue]

    @model_validator(mode="after")
    def matching_artifact(self):
        if self.source_artifact.artifact_id != self.raw_reference.artifact_id:
            raise ValueError("Provenance reference must match its source artifact")
        return self


class ModuleInfo(Model):
    base_address: int | None = Field(default=None, strict=True, ge=0)
    size: int | None = Field(default=None, strict=True, ge=0)
    name: str | None = None
    path: str | None = None
    base_address_hex: Address | None = None
    observation: str | None = None


class HandleInfo(Model):
    value: Address | None = None
    object_address: Address | None = None
    type: str
    name: str | None = None
    granted_access: Address | None = None


class MemoryRegion(Model):
    start: Address
    end: Address | None = None
    protection: str | None = None
    tag: str | None = None
    commit: NonNegative | None = None
    private_memory: bool | None = None
    mapped_file: str | None = None
    hex_preview: str | None = None
    disassembly_preview: str | None = None


class ServiceInfo(Model):
    name: str
    display_name: str | None = None
    state: str | None = None
    start_type: str | None = None
    binary_path: str | None = None
    pid: PID | None = None
    service_dll: str | None = None


class RegistryInfo(Model):
    artifact: str
    hive: str | None = None
    path: str | None = None
    value_name: str | None = None
    value_data: JsonValue = None
    last_write_time: Timestamp | None = None
    run_count: NonNegative | None = None


class DriverInfo(Model):
    name: str | None = None
    path: str | None = None
    start: Address | None = None
    size: NonNegative | None = None
    object_address: Address | None = None
    service_key: str | None = None


class CallbackInfo(Model):
    type: str
    address: Address
    module: str | None = None
    symbol: str | None = None


class PrefetchInfo(Model):
    executable: str
    executable_path: str | None = None
    prefetch_hash: str | None = None
    run_count: NonNegative | None = None
    execution_times: list[Timestamp] = Field(default_factory=list)
    directories: list[str] = Field(default_factory=list)
    volumes: list[dict[str, JsonValue]] = Field(default_factory=list)


class EventLogInfo(Model):
    event_id: int
    provider: str
    channel: str | None = None
    record_id: NonNegative | None = None
    computer: str | None = None


class JournalInfo(Model):
    usn: NonNegative
    reasons: list[str]
    source_info: str | None = None
    file_reference: str | None = None
    parent_reference: str | None = None


class Event(Model):
    schema_version: str = Field(default="1.0", pattern=r"^1\.0$")
    event_id: Identifier
    timestamp: Timestamp
    timestamp_precision: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None
    timestamp_uncertainty: Annotated[float, Field(ge=0, allow_inf_nan=False)] = 0
    timestamp_semantics: Literal[
        "event_time",
        "process_creation",
        "socket_creation",
        "module_load",
        "extraction_time",
        "file_creation",
        "file_modification",
        "file_access",
        "registry_write",
        "process_execution",
        "flow_start",
    ] = "event_time"
    source: Source
    type: str = Field(min_length=1, max_length=128)
    artifact_type: str | None = None
    process: Process | None = None
    file: File | None = None
    module: ModuleInfo | None = None
    handle: HandleInfo | None = None
    memory_region: MemoryRegion | None = None
    service: ServiceInfo | None = None
    registry: RegistryInfo | None = None
    driver: DriverInfo | None = None
    callback: CallbackInfo | None = None
    prefetch: PrefetchInfo | None = None
    event_log: EventLogInfo | None = None
    journal: JournalInfo | None = None
    network: Network | None = None
    user: User | None = None
    hostname: str | None = None
    hash: Hashes | None = None
    source_artifact: SourceArtifact | None = None
    parser: ParserInfo | None = None
    raw_reference: RawReference | None = None
    raw: dict[str, JsonValue] | None = None
    provenance: list[Provenance] = Field(default_factory=list)
    attributes: dict[str, JsonValue] = Field(default_factory=dict)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def consistent_reference(self):
        if self.network and self.network.end_time and self.network.end_time < self.timestamp:
            raise ValueError("Network end_time precedes event timestamp")
        if self.raw_reference and self.source_artifact:
            if self.raw_reference.artifact_id != self.source_artifact.artifact_id:
                raise ValueError("raw_reference must refer to source_artifact.artifact_id")
        return self
