"""MIME tree walking and safe payload decoding.

Every part is attacker-controlled: boundaries may be broken, charsets unknown,
base64 corrupt, and nesting arbitrarily deep. Nothing here may raise on bad input.
"""

from __future__ import annotations

import codecs
import hashlib
from dataclasses import dataclass, field
from email.message import Message

from .models import Finding, MimePart, Severity

MAX_DEPTH = 20
MAX_PARTS = 1000

KNOWN_TRANSFER_ENCODINGS = {"7bit", "8bit", "binary", "base64", "quoted-printable"}


@dataclass
class WalkedPart:
    """A leaf part together with its decoded bytes, used by body/attachment analysis."""

    info: MimePart
    message: Message
    payload: bytes = b""


@dataclass
class MimeTree:
    parts: list[MimePart] = field(default_factory=list)
    leaves: list[WalkedPart] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def walk_mime(msg: Message) -> MimeTree:
    tree = MimeTree()
    _walk(msg, "1", 0, tree)
    return tree


def _walk(part: Message, path: str, depth: int, tree: MimeTree) -> None:
    if len(tree.parts) >= MAX_PARTS:
        if not any(f.code == "MIME_TOO_MANY_PARTS" for f in tree.findings):
            tree.findings.append(Finding(
                "MIME_TOO_MANY_PARTS", Severity.MEDIUM,
                f"Message has more than {MAX_PARTS} MIME parts; the rest were not analyzed.",
            ))
        return
    if depth > MAX_DEPTH:
        tree.findings.append(Finding(
            "MIME_TOO_DEEP", Severity.MEDIUM,
            f"MIME nesting deeper than {MAX_DEPTH} levels at part {path}; not analyzed further.",
            {"part": path},
        ))
        return

    info = MimePart(
        path=path,
        content_type=_safe(part.get_content_type, "application/octet-stream"),
        depth=depth,
        charset=_safe(part.get_content_charset, None),
        transfer_encoding=_header(part, "Content-Transfer-Encoding"),
        disposition=_safe(part.get_content_disposition, None),
        filename=_safe(part.get_filename, None),
        defects=[type(d).__name__ for d in getattr(part, "defects", [])],
    )
    tree.parts.append(info)

    if info.transfer_encoding and info.transfer_encoding.lower() not in KNOWN_TRANSFER_ENCODINGS:
        tree.findings.append(Finding(
            "MIME_UNKNOWN_TRANSFER_ENCODING", Severity.LOW,
            f"Part {path} uses unknown Content-Transfer-Encoding '{info.transfer_encoding}'.",
            {"part": path, "encoding": info.transfer_encoding},
        ))
    if info.defects and depth > 0:  # root defects are already reported by the header rules
        tree.findings.append(Finding(
            "MIME_PART_DEFECTS", Severity.LOW,
            f"Part {path} has structural defects.",
            {"part": path, "defects": info.defects},
        ))

    if part.is_multipart():
        children = part.get_payload()
        if not isinstance(children, list):
            return
        for i, child in enumerate(children, start=1):
            if isinstance(child, Message):
                _walk(child, f"{path}.{i}", depth + 1, tree)
        return

    payload = _decoded_payload(part)
    info.size = len(payload)
    info.sha256 = hashlib.sha256(payload).hexdigest()
    info.is_attachment = info.disposition == "attachment" or bool(info.filename)
    tree.leaves.append(WalkedPart(info=info, message=part, payload=payload))


def is_text_charset(charset: str) -> bool:
    """True if `charset` names a real text codec. Attacker-supplied names may contain
    surrogate escapes (UnicodeError) or name bytes-to-bytes codecs like 'base64'."""
    try:
        return getattr(codecs.lookup(charset), "_is_text_encoding", True)
    except (LookupError, UnicodeError, ValueError):
        return False


def decode_text(payload: bytes, charset: str | None) -> tuple[str, str | None]:
    """Decode bytes to text. Returns (text, problem) where problem names an issue, if any."""
    charset = (charset or "us-ascii").strip().strip('"').lower()
    if not is_text_charset(charset):
        shown = charset.encode("utf-8", "backslashreplace").decode("ascii", "backslashreplace")
        return payload.decode("utf-8", errors="replace"), f"unknown charset '{shown}'"
    try:
        return payload.decode(charset), None
    except (UnicodeError, ValueError, LookupError):
        return payload.decode(charset, errors="replace"), f"invalid bytes for charset '{charset}'"


def _decoded_payload(part: Message) -> bytes:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if isinstance(payload, bytes):
        return payload
    raw = part.get_payload()
    if isinstance(raw, str):
        return raw.encode("utf-8", errors="replace")
    return b""


def _header(part: Message, name: str) -> str | None:
    try:
        value = part.get(name)
    except Exception:
        return None
    return str(value).strip() if value is not None else None


def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default
