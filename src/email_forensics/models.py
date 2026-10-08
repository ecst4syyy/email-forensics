"""Data structures shared across analyzers and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .auth import AuthVerification
    from .msg import MsgInfo
    from .scoring import Assessment
    from .payloads import PayloadAnalysis


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
    format: str = "eml"  # eml, msg, mbox, attached (message inside another message)
    converted: bool = False  # the analysed MIME was rebuilt (from .msg) or re-serialised
    container: str | None = None  # e.g. the mbox file and index, or the parent message part
    container_sha256: str | None = None
    notes: list[str] = field(default_factory=list)


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
class MimePart:
    """One node of the MIME tree. ``path`` uses IMAP-style numbering ("1", "2.1")."""

    path: str
    content_type: str
    depth: int
    charset: str | None = None
    transfer_encoding: str | None = None
    disposition: str | None = None
    filename: str | None = None
    size: int = 0
    sha256: str | None = None
    is_attachment: bool = False
    defects: list[str] = field(default_factory=list)


@dataclass
class Link:
    """A URL reference found in a body part."""

    url: str
    source: str  # "text", "a", "img", "form", "iframe", "meta-refresh", ...
    part: str
    text: str | None = None  # visible anchor text for <a> links


@dataclass
class HtmlForm:
    action: str | None
    method: str | None
    input_types: list[str] = field(default_factory=list)


@dataclass
class HtmlAnalysis:
    part: str
    visible_text: str = ""
    hidden_text: list[str] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    forms: list[HtmlForm] = field(default_factory=list)
    scripts: int = 0
    event_handlers: list[str] = field(default_factory=list)
    embedded_frames: list[str] = field(default_factory=list)
    tracking_pixels: list[str] = field(default_factory=list)
    remote_resources: int = 0
    meta_refresh: str | None = None
    base_href: str | None = None
    truncated: bool = False


@dataclass
class TextBody:
    part: str
    content_type: str
    length: int
    preview: str


@dataclass
class UrlInfo:
    """A unique URL with everything we know about where it appeared."""

    url: str
    scheme: str
    host: str | None
    org_domain: str | None
    sources: list[str] = field(default_factory=list)  # "part:source"
    anchor_texts: list[str] = field(default_factory=list)


@dataclass
class BodyAnalysis:
    parts: list[MimePart] = field(default_factory=list)
    text_bodies: list[TextBody] = field(default_factory=list)
    html: list[HtmlAnalysis] = field(default_factory=list)
    urls: list[UrlInfo] = field(default_factory=list)


@dataclass
class ArchiveMember:
    """A file inside an archive. ``container`` is the path of nested archives, if any."""

    name: str
    size: int
    compressed_size: int | None = None
    encrypted: bool = False
    is_dir: bool = False
    container: str | None = None
    detected_type: str | None = None
    sha256: str | None = None


@dataclass
class ArchiveInfo:
    format: str
    members: list[ArchiveMember] = field(default_factory=list)
    total_uncompressed: int = 0
    encrypted_members: int = 0
    max_nesting: int = 0
    overlapping_entries: bool = False
    truncated: bool = False
    error: str | None = None


@dataclass
class Attachment:
    part: str
    filename: str | None
    content_type: str
    inline: bool
    size: int
    md5: str
    sha1: str
    sha256: str
    extension: str | None = None
    detected_type: str | None = None
    detected_description: str | None = None
    archive: ArchiveInfo | None = None
    urls: list[UrlInfo] = field(default_factory=list)
    payload: PayloadAnalysis | None = None
    extracted_to: str | None = None


@dataclass
class IdentityAnalysis:
    mailer: str | None = None  # raw X-Mailer / User-Agent
    mailer_name: str | None = None
    mailer_category: str | None = None
    php_script: str | None = None
    provider_verdicts: dict[str, dict[str, str]] = field(default_factory=dict)
    recipient_domains: list[str] = field(default_factory=list)
    protected_domain_count: int = 0
    checked_hosts: int = 0


@dataclass
class Report:
    evidence: EvidenceInfo
    headers: HeaderAnalysis
    body: BodyAnalysis = field(default_factory=BodyAnalysis)
    attachments: list[Attachment] = field(default_factory=list)
    identity: IdentityAnalysis = field(default_factory=IdentityAnalysis)
    auth: AuthVerification | None = None
    msg: MsgInfo | None = None
    nested: list[NestedReport] = field(default_factory=list)
    assessment: Assessment | None = None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass
class NestedReport:
    """An email attached to the analysed email, analysed in full."""

    part: str
    filename: str | None
    report: Report


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
