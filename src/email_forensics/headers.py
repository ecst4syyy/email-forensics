"""Header extraction: addresses, ``Received`` chain and ``Authentication-Results``.

This module only extracts facts. Deciding what is suspicious lives in ``rules.py``.
Everything here must tolerate malformed, attacker-controlled input without raising.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime

from .models import AuthResult, HeaderAnalysis, ReceivedHop

_COMMENT_RE = re.compile(r"\([^()]*\)")
_FROM_RE = re.compile(r"\bfrom\s+([^\s;()]+)", re.I)
_BY_RE = re.compile(r"\bby\s+([^\s;()]+)", re.I)
_WITH_RE = re.compile(r"\bwith\s+([^\s;()]+)", re.I)
_ID_RE = re.compile(r"\bid\s+<?([^\s;<>()]+)>?", re.I)
_FOR_RE = re.compile(r"\bfor\s+<?([^\s;<>()]+@[^\s;<>()]+)>?", re.I)
_FROM_CLAUSE_RE = re.compile(r"\bfrom\b(.*?)(?:\bby\b|;|$)", re.I | re.S)
_BRACKET_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def raw_header(msg: EmailMessage, name: str, decode: bool = True) -> str | None:
    """First value of a header as an unfolded string, or None."""
    values = raw_headers(msg, name, decode)
    return values[0] if values else None


def raw_headers(msg: EmailMessage, name: str, decode: bool = True) -> list[str]:
    """All values of a header, unfolded, optionally with RFC 2047 words decoded.

    Address headers must be parsed with ``decode=False`` and have only the display
    names decoded afterwards; decoding first lets an encoded name inject ``<addr>``.
    """
    name = name.lower()
    out = []
    for key, value in msg.raw_items():
        if key.lower() == name:
            value = _unfold(str(value))
            out.append(_decode(value) if decode else value)
    return out


def _decode(value: str) -> str:
    """Decode RFC 2047 encoded-words; fall back to the raw value on any error."""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _unfold(value: str) -> str:
    return re.sub(r"\r?\n[ \t]+", " ", value).strip()


def parse_addresses(value: str | None) -> list[tuple[str, str]]:
    if not value:
        return []
    try:
        pairs = getaddresses([value])
    except Exception:
        return []
    return [(_decode(name), addr) for name, addr in pairs if addr or name]


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError):
        return None
    # Naive datetimes (e.g. "-0000" zone) can't be compared with aware ones; treat as unknown.
    return dt if dt is not None and dt.tzinfo is not None else None


def is_private_ip(ip: str) -> bool | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return not addr.is_global


def _valid_ip(candidate: str) -> str | None:
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def parse_received(raw: str, index: int = 0) -> ReceivedHop:
    hop = ReceivedHop(index=index, raw=raw)

    # Timestamp is everything after the last ';'.
    body, sep, date_part = raw.rpartition(";")
    if not sep:
        body = raw
    else:
        hop.timestamp = parse_date(date_part)

    # Host/keyword matching ignores (comments), which often contain words like "from".
    stripped = body
    while True:
        new = _COMMENT_RE.sub(" ", stripped)
        if new == stripped:
            break
        stripped = new

    for attr, regex in (
        ("from_host", _FROM_RE),
        ("by_host", _BY_RE),
        ("protocol", _WITH_RE),
        ("id", _ID_RE),
        ("for_address", _FOR_RE),
    ):
        m = regex.search(stripped)
        if m:
            setattr(hop, attr, m.group(1))

    # The connecting IP is usually inside the from-clause comment: "(host [1.2.3.4])".
    m = _FROM_CLAUSE_RE.search(body)
    if m:
        clause = m.group(1)
        candidates = _BRACKET_IP_RE.findall(clause) + _IPV4_RE.findall(clause)
        for candidate in candidates:
            ip = _valid_ip(candidate)
            if ip:
                hop.from_ip = ip
                hop.ip_is_private = is_private_ip(ip)
                break
    return hop


def parse_received_chain(values: list[str]) -> list[ReceivedHop]:
    """Parse ``Received`` headers and return them oldest-first with hop delays.

    Relays prepend ``Received`` headers, so the last one in the message is the first hop.
    """
    hops = [parse_received(v) for v in reversed(values)]
    prev_ts = None
    for i, hop in enumerate(hops, start=1):
        hop.index = i
        if hop.timestamp and prev_ts:
            hop.delay_seconds = (hop.timestamp - prev_ts).total_seconds()
        if hop.timestamp:
            prev_ts = hop.timestamp
    return hops


def parse_authentication_results(value: str) -> list[AuthResult]:
    """Parse one RFC 8601 ``Authentication-Results`` header."""
    text = value
    while True:
        new = _COMMENT_RE.sub(" ", text)
        if new == text:
            break
        text = new

    parts = [p.strip() for p in text.split(";")]
    if not parts or not parts[0]:
        return []
    authserv_id = parts[0].split()[0]
    results = []
    for part in parts[1:]:
        tokens = part.split()
        if not tokens or "=" not in tokens[0]:
            continue
        method, _, result = tokens[0].partition("=")
        method = method.split("/")[0].lower()  # strip optional method version
        props = {}
        for tok in tokens[1:]:
            if "=" in tok:
                k, _, v = tok.partition("=")
                props[k.lower()] = v.strip('"')
        results.append(AuthResult(authserv_id, method, result.lower(), props))
    return results


def analyze_headers(msg: EmailMessage) -> HeaderAnalysis:
    h = HeaderAnalysis()
    h.header_count = len(msg.keys())
    h.subject = raw_header(msg, "Subject")
    h.date = parse_date(raw_header(msg, "Date"))
    h.message_id = raw_header(msg, "Message-ID")
    h.x_mailer = raw_header(msg, "X-Mailer") or raw_header(msg, "User-Agent")
    h.x_originating_ip = raw_header(msg, "X-Originating-IP")

    from_addrs = parse_addresses(raw_header(msg, "From", decode=False))
    if from_addrs:
        h.from_display_name = from_addrs[0][0] or None
        h.from_address = from_addrs[0][1].lower() or None

    h.return_path = _first_address(msg, "Return-Path")
    h.sender = _first_address(msg, "Sender")
    h.reply_to = _all_addresses(msg, "Reply-To")
    h.to = _all_addresses(msg, "To")
    h.cc = _all_addresses(msg, "Cc")

    h.hops = parse_received_chain(raw_headers(msg, "Received"))
    for value in raw_headers(msg, "Authentication-Results"):
        h.auth_results.extend(parse_authentication_results(value))
    return h


def _all_addresses(msg: EmailMessage, name: str) -> list[str]:
    joined = ", ".join(raw_headers(msg, name, decode=False))
    return [addr.lower() for _, addr in parse_addresses(joined) if addr]


def _first_address(msg: EmailMessage, name: str) -> str | None:
    addrs = _all_addresses(msg, name)
    return addrs[0] if addrs else None
