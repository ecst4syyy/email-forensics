"""Load evidence files read-only and record integrity hashes before parsing."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

from . import __version__
from .models import EvidenceInfo

# Guard against accidentally feeding huge files (e.g. a whole mailbox) to the .eml parser.
MAX_MESSAGE_BYTES = 100 * 1024 * 1024


class EvidenceError(Exception):
    pass


def load_eml(path: str | Path) -> tuple[EvidenceInfo, EmailMessage]:
    path = Path(path)
    if not path.is_file():
        raise EvidenceError(f"not a file: {path}")
    size = path.stat().st_size
    if size > MAX_MESSAGE_BYTES:
        raise EvidenceError(f"file too large ({size} bytes > {MAX_MESSAGE_BYTES})")

    raw = path.read_bytes()
    info = EvidenceInfo(
        path=str(path),
        size=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        md5=hashlib.md5(raw).hexdigest(),
        analyzed_at=datetime.now(timezone.utc),
        tool_version=__version__,
    )
    return info, parse_bytes(raw)


def parse_bytes(raw: bytes) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes(raw)
