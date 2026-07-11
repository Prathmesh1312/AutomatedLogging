from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class Ecs(BaseModel):
    version: str = "8.11.0"

class Event(BaseModel):
    category: List[str] = Field(default_factory=list)
    type: List[str] = Field(default_factory=list)
    action: str
    outcome: str
    reason: Optional[str] = None

class GeoLocation(BaseModel):
    lat: float
    lon: float

class Geo(BaseModel):
    city_name: Optional[str] = None
    country_iso_code: Optional[str] = None
    location: Optional[GeoLocation] = None

class Source(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None
    geo: Optional[Geo] = None

class Destination(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None

class User(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    roles: Optional[List[str]] = None

class OsInfo(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None

class Device(BaseModel):
    id: Optional[str] = None
    model: Optional[str] = None
    os: Optional[OsInfo] = None

class ParentProcess(BaseModel):
    name: Optional[str] = None
    pid: Optional[int] = None

class Process(BaseModel):
    name: Optional[str] = None
    command_line: Optional[str] = None
    pid: Optional[int] = None
    parent: Optional[ParentProcess] = None

class Url(BaseModel):
    original: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None
    port: Optional[int] = None

class HttpRequest(BaseModel):
    method: str
    body_bytes: Optional[int] = None

class HttpResponse(BaseModel):
    status_code: int
    body_bytes: Optional[int] = None

class Http(BaseModel):
    request: Optional[HttpRequest] = None
    response: Optional[HttpResponse] = None

class Database(BaseModel):
    query: Optional[str] = None
    instance: Optional[str] = None
    user: Optional[str] = None

class SimulatorContext(BaseModel):
    attack: bool = False
    mitre_id: Optional[str] = None
    attack_name: Optional[str] = None
    risk_level: str = "info"  # info, low, medium, high
    entity_type: str         # customer, employee, infrastructure
    persona: str             # e.g., regular_customer, malicious_admin, atm_skimmer
    session_id: Optional[str] = None

class ECSLog(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True
    )

    timestamp: datetime = Field(..., alias="@timestamp")
    ecs: Ecs = Field(default_factory=Ecs)
    event: Event
    source: Optional[Source] = None
    destination: Optional[Destination] = None
    user: Optional[User] = None
    device: Optional[Device] = None
    process: Optional[Process] = None
    url: Optional[Url] = None
    http: Optional[Http] = None
    database: Optional[Database] = None
    simulator: SimulatorContext
    message: str

    def to_json(self) -> str:
        # Standardize timestamp formatting to ISO format with Z suffix for Elasticsearch compatibility
        return self.model_dump_json(by_alias=True, exclude_none=True)
