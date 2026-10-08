"""Load evidence read-only, record integrity hashes, and detect the input format.

Supported: RFC 5322 ``.eml`` files, Outlook ``.msg`` files (converted to MIME) and
``mbox`` mailboxes (one evidence item per message). The original file is hashed
before anything else; nothing is ever written back.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from datetime import datetime, timezone
from email import policy
from email.errors import MessageError
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

from . import __version__
from .cfb import SIGNATURE as CFB_SIGNATURE
from .models import EvidenceInfo
from .msg import MsgInfo, is_msg, msg_to_message

# Guard against accidentally treating something huge as a single message.
MAX_MESSAGE_BYTES = 100 * 1024 * 1024
MAX_MBOX_MESSAGES = 1_000_000
_MBOX_FROM_RE = re.compile(rb"^From \S*.*\d{4}\s*$")


class EvidenceError(Exception):
    pass


def _info(path: str, raw: bytes, fmt: str, **extra) -> EvidenceInfo:
    return EvidenceInfo(
        path=path, size=len(raw), sha256=hashlib.sha256(raw).hexdigest(), md5=hashlib.md5(raw).hexdigest(),
        analyzed_at=datetime.now(timezone.utc), tool_version=__version__, format=fmt, **extra,
    )


def detect_format(path: str | Path) -> str:
    """'msg', 'mbox' or 'eml', from the file content (the extension is only a tie-breaker)."""
    with open(path, "rb") as fh:
        head = fh.read(65536)
    if head.startswith(CFB_SIGNATURE):
        return "msg"
    first_line = head.split(b"\n", 1)[0].rstrip(b"\r")
    if first_line.startswith(b"From ") and (
        _MBOX_FROM_RE.match(first_line) or str(path).lower().endswith((".mbox", ".mbx", ".mbs"))
    ):
        return "mbox"
    return "eml"


def load_eml(path: str | Path) -> tuple[EvidenceInfo, EmailMessage]:
    info, _, msg, _ = load_evidence(path)
    return info, msg


def load_evidence(path: str | Path) -> tuple[EvidenceInfo, bytes, EmailMessage, MsgInfo | None]:
    """Read one message file (.eml or .msg).

    Returns integrity info for the original file, the MIME bytes to analyse, the
    parsed message, and Outlook metadata for .msg input.
    """
    path = Path(path)
    if not path.is_file():
        raise EvidenceError(f"not a file: {path}")
    size = path.stat().st_size
    if size > MAX_MESSAGE_BYTES:
        raise EvidenceError(f"file too large ({size} bytes > {MAX_MESSAGE_BYTES}); mbox files are read per message")
    raw = path.read_bytes()
    if raw.startswith(CFB_SIGNATURE):
        if not is_msg(raw):
            raise EvidenceError(f"{path} is an OLE compound file but not an Outlook message")
        return load_msg_bytes(str(path), raw)
    return _info(str(path), raw, "eml"), raw, parse_bytes(raw), None


def load_msg_bytes(label: str, raw: bytes, **extra) -> tuple[EvidenceInfo, bytes, EmailMessage, MsgInfo]:
    try:
        message, msg_info = msg_to_message(raw)
    except ValueError as exc:
        raise EvidenceError(f"{label}: {exc}") from exc
    try:
        mime = message.as_bytes()
    except (UnicodeError, ValueError, TypeError, MessageError):
        try:
            mime = message.as_bytes(policy=message.policy.clone(utf8=True))
        except (UnicodeError, ValueError, TypeError, MessageError) as exc:
            raise EvidenceError(f"{label}: could not rebuild MIME from .msg: {exc}") from exc
    info = _info(label, raw, "msg", converted=True,
                 notes=["MIME rebuilt from Outlook MAPI properties; hashes are of the original .msg file"]
                 + msg_info.notes, **extra)
    return info, mime, parse_bytes(mime), msg_info


def iter_mbox(path: str | Path) -> Iterator[tuple[EvidenceInfo, bytes, EmailMessage]]:
    """Yield each message of an mbox file with its own integrity info.

    The whole mailbox is hashed first (streaming); every message records the
    mailbox hash and its 1-based index as its container.
    """
    path = Path(path)
    if not path.is_file():
        raise EvidenceError(f"not a file: {path}")
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha.update(chunk)
    container_sha = sha.hexdigest()

    index = 0
    for raw in _split_mbox(path):
        index += 1
        if index > MAX_MBOX_MESSAGES:
            break
        label = f"{path}#{index}"
        if len(raw) > MAX_MESSAGE_BYTES:
            raise EvidenceError(f"{label}: message larger than {MAX_MESSAGE_BYTES} bytes")
        info = _info(label, raw, "mbox", container=f"{path} message {index}", container_sha256=container_sha)
        yield info, raw, parse_bytes(raw)


def _split_mbox(path: Path) -> Iterator[bytes]:
    """Split on 'From ' separator lines and undo mboxrd '>From ' quoting."""
    current: list[bytes] | None = None
    size = 0
    with open(path, "rb") as fh:
        for line in fh:
            if line.startswith(b"From ") and (current is None or _MBOX_FROM_RE.match(line.rstrip(b"\r\n"))
                                              or line.rstrip(b"\r\n") == b"From "):
                if current is not None:
                    yield _finish(current)
                current, size = [], 0
                continue
            if current is None:
                current = []
            if re.match(rb"^>+From ", line):
                line = line[1:]
            size += len(line)
            if size <= MAX_MESSAGE_BYTES + 1:
                current.append(line)
    if current:
        yield _finish(current)


def _finish(lines: list[bytes]) -> bytes:
    raw = b"".join(lines)
    # The blank line before the next separator belongs to the mbox format, not the message.
    if raw.endswith(b"\r\n\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n\n"):
        raw = raw[:-1]
    return raw


def parse_bytes(raw: bytes) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes(raw)
