"""Outlook .msg (MS-OXMSG) reading and conversion to an internet message.

A .msg file is a Compound File holding MAPI properties. When it carries the
original internet headers (PR_TRANSPORT_MESSAGE_HEADERS) those are used as-is;
the body and attachments are rebuilt as MIME from the properties. Because the
MIME body is reconstructed, DKIM body hashes of a .msg can not be verified.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email import policy
from email.message import EmailMessage
from email.parser import HeaderParser
from email.utils import format_datetime, formataddr

from .cfb import CompoundFile, open_cfb

MAX_DEPTH = 5
MAX_ATTACHMENTS = 500
_DROP_TRANSPORT = {"content-type", "content-transfer-encoding", "mime-version"}

# Property ids
PR_SUBJECT, PR_TRANSPORT_HEADERS, PR_BODY, PR_HTML, PR_RTF_COMPRESSED = 0x0037, 0x007D, 0x1000, 0x1013, 0x1009
PR_SENDER_NAME, PR_SENDER_EMAIL, PR_SENDER_SMTP, PR_SENT_REPR_SMTP = 0x0C1A, 0x0C1F, 0x5D01, 0x5D02
PR_MESSAGE_ID, PR_MESSAGE_CLASS, PR_CODEPAGE, PR_IN_REPLY_TO = 0x1035, 0x001A, 0x3FFD, 0x1042
PR_SUBMIT_TIME, PR_DELIVERY_TIME, PR_CREATION_TIME, PR_LAST_MOD_TIME = 0x0039, 0x0E06, 0x3007, 0x3008
PR_LAST_MODIFIER_NAME = 0x3FFA
PR_DISPLAY_NAME, PR_SMTP_ADDRESS, PR_EMAIL_ADDRESS, PR_RECIPIENT_TYPE = 0x3001, 0x39FE, 0x3003, 0x0C15
PR_ATTACH_LONG_FILENAME, PR_ATTACH_FILENAME, PR_ATTACH_MIME, PR_ATTACH_DATA = 0x3707, 0x3704, 0x370E, 0x3701
PR_ATTACH_METHOD, PR_ATTACH_CONTENT_ID, PR_ATTACH_HIDDEN = 0x3705, 0x3712, 0x7FFE


@dataclass
class MsgInfo:
    message_class: str | None = None
    has_transport_headers: bool = False
    submit_time: str | None = None
    delivery_time: str | None = None
    creation_time: str | None = None
    last_modified_time: str | None = None
    last_modified_by: str | None = None
    sender_smtp: str | None = None
    attachments: int = 0
    notes: list[str] = field(default_factory=list)


def is_msg(data: bytes) -> bool:
    cf = open_cfb(data)
    return cf is not None and _looks_like_msg(cf)


def _looks_like_msg(cf: CompoundFile) -> bool:
    return any(e.path[0].lower().startswith(("__substg1.0_", "__properties_version1.0")) for e in cf.streams())


class _Props:
    """MAPI properties of one object (message, recipient or attachment) in a storage."""

    def __init__(self, cf: CompoundFile, prefix: tuple[str, ...], header_size: int, codepage: str = "cp1252"):
        self.cf, self.prefix, self.codepage = cf, prefix, codepage
        self.fixed: dict[int, tuple[int, bytes]] = {}
        raw = self._read("__properties_version1.0")
        if raw:
            for off in range(header_size, len(raw) - 15, 16):
                tag, _, value = struct.unpack_from("<II8s", raw, off)
                self.fixed[tag >> 16] = (tag & 0xFFFF, value)

    def _read(self, name: str) -> bytes | None:
        try:
            return self.cf.read_path(*self.prefix, name)
        except ValueError:
            return None

    def string(self, pid: int) -> str | None:
        raw = self._read(f"__substg1.0_{pid:04X}001F")
        if raw is not None:
            return raw.decode("utf-16-le", "replace").rstrip("\x00")
        raw = self._read(f"__substg1.0_{pid:04X}001E")
        if raw is not None:
            try:
                return raw.decode(self.codepage, "replace").rstrip("\x00")
            except LookupError:
                return raw.decode("cp1252", "replace").rstrip("\x00")
        return None

    def binary(self, pid: int) -> bytes | None:
        return self._read(f"__substg1.0_{pid:04X}0102")

    def int(self, pid: int) -> int | None:
        entry = self.fixed.get(pid)
        if entry and entry[0] in (0x0003, 0x0002, 0x000B):
            return struct.unpack_from("<i", entry[1])[0]
        return None

    def time(self, pid: int) -> str | None:
        entry = self.fixed.get(pid)
        if entry and entry[0] == 0x0040:
            ticks = struct.unpack_from("<Q", entry[1])[0]
            try:
                return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)).isoformat()
            except OverflowError:
                return None
        return None


def _children(cf: CompoundFile, prefix: tuple[str, ...], kind: str) -> list[tuple[str, ...]]:
    found = set()
    for e in cf.storages():
        if len(e.path) == len(prefix) + 1 and tuple(p.lower() for p in e.path[:-1]) == tuple(p.lower() for p in prefix):
            if e.path[-1].lower().startswith(kind):
                found.add(e.path)
    return sorted(found, key=lambda p: p[-1].lower())


def msg_to_message(data: bytes) -> tuple[EmailMessage, MsgInfo]:
    cf = open_cfb(data)
    if cf is None or not _looks_like_msg(cf):
        raise ValueError("not an Outlook .msg file")
    return _convert(cf, (), 32, 0)


def _convert(cf: CompoundFile, prefix: tuple[str, ...], header_size: int, depth: int) -> tuple[EmailMessage, MsgInfo]:
    props = _Props(cf, prefix, header_size)
    cp = props.int(PR_CODEPAGE)
    if cp:
        props.codepage = {65001: "utf-8", 20127: "ascii"}.get(cp, f"cp{cp}")
    info = MsgInfo(message_class=props.string(PR_MESSAGE_CLASS))
    info.submit_time, info.delivery_time = props.time(PR_SUBMIT_TIME), props.time(PR_DELIVERY_TIME)
    info.creation_time, info.last_modified_time = props.time(PR_CREATION_TIME), props.time(PR_LAST_MOD_TIME)
    info.last_modified_by = props.string(PR_LAST_MODIFIER_NAME)
    info.sender_smtp = props.string(PR_SENDER_SMTP) or props.string(PR_SENT_REPR_SMTP)

    msg = EmailMessage(policy=policy.default)
    transport = props.string(PR_TRANSPORT_HEADERS)
    if transport and transport.strip():
        info.has_transport_headers = True
        headers = HeaderParser(policy=policy.compat32).parsestr(transport.replace("\r\n", "\n").strip() + "\n\n")
        for name, value in headers.items():
            if name.lower() not in _DROP_TRANSPORT:
                msg._headers.append((name, _raw_header_text(value)))  # keep the original (folded) text
    else:
        info.notes.append("no transport headers: header fields were rebuilt from MAPI properties "
                          "(typical of drafts and sent items)")
        _synthesize_headers(msg, props, cf, prefix, info)

    plain = props.string(PR_BODY)
    html = props.binary(PR_HTML)
    if html is None:
        html_text = props.string(PR_HTML)
        html = html_text.encode("utf-8") if html_text else None
    rtf = None
    compressed = props.binary(PR_RTF_COMPRESSED)
    if compressed:
        try:
            rtf = decompress_rtf(compressed)
        except ValueError as exc:
            info.notes.append(f"compressed RTF body could not be decoded: {exc}")

    if plain is not None:
        msg.set_content(plain)
    if html is not None:
        charset = _html_charset(html)
        text = html.decode(charset, "replace")
        if plain is not None:
            msg.add_alternative(text, subtype="html")
        else:
            msg.set_content(text, subtype="html")
    if plain is None and html is None:
        msg.set_content("" if rtf is None else _rtf_to_text(rtf))
    if rtf is not None and plain is None and html is None:
        msg.add_attachment(rtf, maintype="text", subtype="rtf", filename="body.rtf")
        info.notes.append("body only available as RTF; attached as body.rtf")

    for att_prefix in _children(cf, prefix, "__attach_version1.0_#")[:MAX_ATTACHMENTS]:
        _add_attachment(cf, msg, att_prefix, depth, info)
    return msg, info


def _raw_header_text(value: str) -> str:
    """Carry non-ASCII header text through as its UTF-8 bytes (surrogateescape), the way the
    email package represents raw 8-bit headers, so serialisation never fails."""
    # A line break not followed by whitespace would end the header (and is refused by the
    # generator as header injection); turn it into a fold.
    value = re.sub(r"\r\n?|\n", "\n", value)
    value = re.sub(r"\n(?![ \t])", "\n ", value).rstrip("\n ")
    if value.isascii():
        return value
    return value.encode("utf-8", "surrogatepass").decode("ascii", "surrogateescape")


def _set_raw(msg: EmailMessage, name: str, value: str) -> None:
    """Add a header as raw text: the stdlib's structured parsing can crash on hostile values."""
    msg._headers.append((name, _raw_header_text(value)))


def _synthesize_headers(msg: EmailMessage, props: _Props, cf: CompoundFile, prefix, info: MsgInfo) -> None:
    sender = props.string(PR_SENDER_SMTP) or props.string(PR_SENDER_EMAIL)
    name = props.string(PR_SENDER_NAME)
    if sender:
        _set_raw(msg, "From", formataddr((name or "", sender)))
    to, cc = [], []
    for rp in _children(cf, prefix, "__recip_version1.0_#"):
        r = _Props(cf, rp, 8)
        addr = r.string(PR_SMTP_ADDRESS) or r.string(PR_EMAIL_ADDRESS)
        if not addr:
            continue
        entry = formataddr((r.string(PR_DISPLAY_NAME) or "", addr))
        (cc if r.int(PR_RECIPIENT_TYPE) == 2 else to if r.int(PR_RECIPIENT_TYPE) in (1, None) else []).append(entry)
    if to:
        _set_raw(msg, "To", ", ".join(to))
    if cc:
        _set_raw(msg, "Cc", ", ".join(cc))
    subject = props.string(PR_SUBJECT)
    if subject is not None:
        _set_raw(msg, "Subject", subject)
    when = info.submit_time or info.delivery_time or info.creation_time
    if when:
        _set_raw(msg, "Date", format_datetime(datetime.fromisoformat(when)))
    mid = props.string(PR_MESSAGE_ID)
    if mid:
        _set_raw(msg, "Message-ID", mid)
    reply = props.string(PR_IN_REPLY_TO)
    if reply:
        _set_raw(msg, "In-Reply-To", reply)


def _add_attachment(cf: CompoundFile, msg: EmailMessage, prefix: tuple[str, ...], depth: int, info: MsgInfo) -> None:
    a = _Props(cf, prefix, 8)
    method = a.int(PR_ATTACH_METHOD) or 1
    filename = a.string(PR_ATTACH_LONG_FILENAME) or a.string(PR_ATTACH_FILENAME)
    mime = (a.string(PR_ATTACH_MIME) or "application/octet-stream").strip().lower()
    if method == 5:  # embedded message
        sub = prefix + ("__substg1.0_3701000D",)
        if cf.find(*sub) is None or depth >= MAX_DEPTH:
            info.notes.append(f"embedded message {'/'.join(prefix)} skipped")
            return
        inner, inner_info = _convert(cf, sub, 24, depth + 1)
        info.notes += [f"embedded message: {n}" for n in inner_info.notes]
        msg.add_attachment(inner)
        part = msg.get_payload()[-1] if msg.is_multipart() else None
        if part is not None and filename:
            del part["Content-Disposition"]
            part.add_header("Content-Disposition", "attachment", filename=filename)
        info.attachments += 1
        return
    data = a.binary(PR_ATTACH_DATA)
    if data is None:
        info.notes.append(f"attachment {filename or '/'.join(prefix)} (method {method}) has no inline data")
        return
    maintype, _, subtype = mime.partition("/")
    if not subtype or maintype in ("multipart", "message") or "/" in subtype:
        maintype, subtype = "application", "octet-stream"
    msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename or "attachment.bin")
    part = msg.get_payload()[-1]
    cid = a.string(PR_ATTACH_CONTENT_ID)
    if cid:
        part["Content-ID"] = f"<{cid.strip('<>')}>"
    info.attachments += 1


def _html_charset(html: bytes) -> str:
    m = re.search(rb"charset=[\"']?([\w-]+)", html[:2048], re.I)
    name = m.group(1).decode("ascii") if m else "utf-8"
    try:
        "".encode(name)
        return name
    except LookupError:
        return "utf-8"


def _rtf_to_text(rtf: bytes) -> str:
    """Very rough RTF-to-text for previews (control words and groups stripped)."""
    text = rtf.decode("latin-1", "replace")
    text = re.sub(r"\\par[d]?\b", "\n", text)
    text = re.sub(r"\{\\\*[^{}]*\}", "", text)
    text = re.sub(r"\\'([0-9a-f]{2})", lambda m: bytes([int(m.group(1), 16)]).decode("cp1252", "replace"), text)
    text = re.sub(r"\\[a-zA-Z]+-?\d* ?|[{}]", "", text)
    return text.strip()


# --------------------------------------------------------------------------- compressed RTF (MS-OXRTFCP)

_RTF_PREBUF = (b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript "
               b"\\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par "
               b"\\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx")
MAX_RTF = 32 * 1024 * 1024


def decompress_rtf(data: bytes) -> bytes:
    if len(data) < 16:
        raise ValueError("compressed RTF header too short")
    comp_size, raw_size, magic, _ = struct.unpack_from("<IIII", data, 0)
    if raw_size > MAX_RTF:
        raise ValueError("RTF too large")
    body = data[16:4 + comp_size] if comp_size >= 12 else data[16:]
    if magic == 0x414C454D:  # "MELA": stored uncompressed
        return body[:raw_size]
    if magic != 0x75465A4C:  # "LZFu"
        raise ValueError("unknown compressed RTF type")
    window = bytearray(4096)
    window[: len(_RTF_PREBUF)] = _RTF_PREBUF
    wpos = len(_RTF_PREBUF)
    out = bytearray()
    pos = 0
    while pos < len(body):
        control = body[pos]
        pos += 1
        for bit in range(8):
            if pos >= len(body):
                break
            if control & (1 << bit):
                if pos + 2 > len(body):
                    return bytes(out)
                ref = (body[pos] << 8) | body[pos + 1]
                pos += 2
                offset, length = ref >> 4, (ref & 0x0F) + 2
                if offset == wpos:
                    return bytes(out)
                for i in range(length):
                    c = window[(offset + i) % 4096]
                    out.append(c)
                    window[wpos] = c
                    wpos = (wpos + 1) % 4096
            else:
                c = body[pos]
                pos += 1
                out.append(c)
                window[wpos] = c
                wpos = (wpos + 1) % 4096
            if len(out) > MAX_RTF:
                raise ValueError("decompressed RTF too large")
    return bytes(out)
