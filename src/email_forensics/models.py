"""Data structures shared across analyzers and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high"].index(self.value)


@dataclass
class Finding:
    """A single observation produced by an analyzer.

    `code` is a stable identifier (e.g. ``HDR_REPLY_TO_MISMATCH``) that tests and
    downstream tools can rely on; `message` is the human-readable explanation.
    """

    code: str
    severity: Severity
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceInfo:
    """Integrity data for the original evidence file."""

    path: str
    size: int
    sha256: str
    md5: str
    analyzed_at: datetime
    tool_version: str


@dataclass
class ReceivedHop:
    """One parsed ``Received:`` header, in chronological order (index 1 = first hop)."""

    index: int
    raw: str
    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    protocol: str | None = None
    id: str | None = None
    for_address: str | None = None
    timestamp: datetime | None = None
    delay_seconds: float | None = None
    ip_is_private: bool | None = None


@dataclass
class AuthResult:
    """One method result from an ``Authentication-Results`` header."""

    authserv_id: str
    method: str
    result: str
    properties: dict[str, str] = field(default_factory=dict)


@dataclass
class HeaderAnalysis:
    subject: str | None = None
    date: datetime | None = None
    message_id: str | None = None
    from_address: str | None = None
    from_display_name: str | None = None
    return_path: str | None = None
    reply_to: list[str] = field(default_factory=list)
    sender: str | None = None
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    x_mailer: str | None = None
    x_originating_ip: str | None = None
    hops: list[ReceivedHop] = field(default_factory=list)
    auth_results: list[AuthResult] = field(default_factory=list)
    header_count: int = 0


@dataclass
class Report:
    evidence: EvidenceInfo
    headers: HeaderAnalysis
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    return value
