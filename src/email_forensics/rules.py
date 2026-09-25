"""Header rules: turn extracted header facts into findings."""

from __future__ import annotations

import base64
import binascii
import re
from email.message import EmailMessage

from .domains import domain_of, org_domain
from .headers import parse_addresses, raw_headers
from .mime import is_text_charset
from .models import Finding, HeaderAnalysis, Severity
from .textcheck import invisible_char_findings

# RFC 5322 §3.6: these headers must appear at most once. Duplicates are a known
# trick to show one value to the user and another to filters.
SINGLETON_HEADERS = ("From", "Sender", "Reply-To", "To", "Cc", "Subject", "Date", "Message-ID")

CLOCK_TOLERANCE_SECONDS = 5 * 60
LONG_DELAY_SECONDS = 60 * 60
DATE_SKEW_SECONDS = 60 * 60

_AUTH_SEVERITY = {
    "fail": Severity.HIGH,
    "softfail": Severity.MEDIUM,
    "permerror": Severity.LOW,
    "temperror": Severity.LOW,
    "neutral": Severity.LOW,
    "none": Severity.LOW,
    "policy": Severity.LOW,
}

_ENCODED_WORD_RE = re.compile(r"=\?([^?\s]+)\?([bBqQ])\?([^?\s]*)\?=")
ENCODED_HEADERS = ("Subject", "From", "To", "Cc", "Reply-To", "Sender")

_EMBEDDED_ADDR_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


def _same_org(a: str | None, b: str | None) -> bool:
    return org_domain(domain_of(a)) == org_domain(domain_of(b))


def run_header_rules(msg: EmailMessage, h: HeaderAnalysis) -> list[Finding]:
    findings: list[Finding] = []
    findings += _check_structure(msg, h)
    findings += _check_identity(msg, h)
    findings += _check_authentication(h)
    findings += _check_timeline(h)
    findings += _check_origin(h)
    findings += _check_encoding(msg, h)
    return findings


def _check_structure(msg: EmailMessage, h: HeaderAnalysis) -> list[Finding]:
    out = []
    for name in SINGLETON_HEADERS:
        values = raw_headers(msg, name)
        if len(values) > 1:
            out.append(Finding(
                "HDR_DUPLICATE", Severity.MEDIUM,
                f"Header '{name}' appears {len(values)} times; clients and filters may disagree on which to show.",
                {"header": name, "values": values},
            ))
    if not raw_headers(msg, "From"):
        out.append(Finding("HDR_MISSING_FROM", Severity.MEDIUM, "Message has no From header."))
    if h.date is None:
        present = bool(raw_headers(msg, "Date"))
        out.append(Finding(
            "HDR_BAD_DATE" if present else "HDR_MISSING_DATE", Severity.LOW,
            "Date header is unparseable." if present else "Message has no Date header.",
        ))
    if not h.message_id:
        out.append(Finding("HDR_MISSING_MESSAGE_ID", Severity.LOW,
                           "Message has no Message-ID; legitimate MTAs normally add one."))

    defects = [type(d).__name__ for d in msg.defects]
    if defects:
        out.append(Finding("PARSE_DEFECTS", Severity.LOW,
                           "The parser reported structural defects in the message.",
                           {"defects": defects}))
    return out


def _check_identity(msg: EmailMessage, h: HeaderAnalysis) -> list[Finding]:
    out = []
    from_addr = h.from_address

    # Multiple addresses in From is legal but rare, and used to confuse displays.
    from_values = raw_headers(msg, "From", decode=False)
    if from_values and len(parse_addresses(from_values[0])) > 1:
        out.append(Finding("HDR_MULTIPLE_FROM_ADDRESSES", Severity.MEDIUM,
                           "From header contains more than one address.",
                           {"from": from_values[0]}))

    if from_addr:
        for embedded in embedded_addresses(h.from_display_name):
            if org_domain(domain_of(embedded)) != org_domain(domain_of(from_addr)):
                out.append(Finding(
                    "HDR_DISPLAY_NAME_SPOOF", Severity.HIGH,
                    f"Display name shows '{embedded}' but the real sender is '{from_addr}'.",
                    {"display_name": h.from_display_name, "from": from_addr},
                ))
                break

    if from_addr and h.return_path and not _same_org(from_addr, h.return_path):
        out.append(Finding(
            "HDR_RETURN_PATH_MISMATCH", Severity.LOW,
            "Envelope sender (Return-Path) domain differs from From domain. "
            "Common for mailing services, but also for spoofing.",
            {"from": from_addr, "return_path": h.return_path},
        ))

    for reply_to in h.reply_to:
        if from_addr and not _same_org(from_addr, reply_to):
            out.append(Finding(
                "HDR_REPLY_TO_MISMATCH", Severity.MEDIUM,
                "Replies go to a different domain than the sender, a common BEC pattern.",
                {"from": from_addr, "reply_to": reply_to},
            ))

    if from_addr and h.sender and not _same_org(from_addr, h.sender):
        out.append(Finding(
            "HDR_SENDER_MISMATCH", Severity.LOW,
            "Sender header domain differs from From domain.",
            {"from": from_addr, "sender": h.sender},
        ))

    if from_addr and h.message_id:
        mid_domain = h.message_id.strip().strip("<>").rpartition("@")[2]
        if mid_domain and org_domain(mid_domain) != org_domain(domain_of(from_addr)):
            out.append(Finding(
                "HDR_MESSAGE_ID_DOMAIN_MISMATCH", Severity.INFO,
                "Message-ID domain differs from From domain (shows which system generated the message).",
                {"from": from_addr, "message_id_domain": mid_domain},
            ))
    return out


def _check_authentication(h: HeaderAnalysis) -> list[Finding]:
    if not h.auth_results:
        return [Finding("AUTH_RESULTS_MISSING", Severity.INFO,
                        "No Authentication-Results header; SPF/DKIM/DMARC verdicts unknown.")]
    out = []
    ids = sorted({r.authserv_id for r in h.auth_results})
    if len(ids) > 1:
        out.append(Finding(
            "AUTH_MULTIPLE_SERVERS", Severity.INFO,
            "Authentication-Results from several servers; only trust ones added by your own infrastructure.",
            {"authserv_ids": ids},
        ))
    for r in h.auth_results:
        sev = _AUTH_SEVERITY.get(r.result)
        if sev is None:
            continue
        out.append(Finding(
            f"AUTH_{r.method.upper()}_{r.result.upper()}", sev,
            f"{r.method.upper()} result '{r.result}' reported by {r.authserv_id}.",
            {"authserv_id": r.authserv_id, **r.properties},
        ))

    # DMARC alignment: a DKIM pass only helps if its d= domain aligns with From.
    from_org = org_domain(domain_of(h.from_address))
    dkim_passes = [r for r in h.auth_results if r.method == "dkim" and r.result == "pass"]
    if from_org and dkim_passes:
        signers = {r.properties.get("header.d", "").lower() for r in dkim_passes} - {""}
        if signers and not any(org_domain(d) == from_org for d in signers):
            out.append(Finding(
                "AUTH_DKIM_NOT_ALIGNED", Severity.LOW,
                "DKIM passed, but only for domains unrelated to the From domain.",
                {"from_domain": from_org, "dkim_domains": sorted(signers)},
            ))
    return out


def _check_timeline(h: HeaderAnalysis) -> list[Finding]:
    out = []
    if not h.hops:
        out.append(Finding("RCV_NO_HOPS", Severity.LOW,
                           "No Received headers; the message may not have passed through SMTP."))
        return out

    for hop in h.hops:
        if hop.timestamp is None:
            out.append(Finding("RCV_BAD_TIMESTAMP", Severity.LOW,
                               f"Received hop {hop.index} has no parseable timestamp.",
                               {"hop": hop.index, "raw": hop.raw}))
            continue
        if hop.delay_seconds is None:
            continue
        if hop.delay_seconds < -CLOCK_TOLERANCE_SECONDS:
            out.append(Finding(
                "RCV_TIME_REVERSAL", Severity.MEDIUM,
                f"Hop {hop.index} is timestamped {-hop.delay_seconds:.0f}s before the previous hop. "
                "Could be clock skew or forged Received headers.",
                {"hop": hop.index, "delay_seconds": hop.delay_seconds},
            ))
        elif hop.delay_seconds > LONG_DELAY_SECONDS:
            out.append(Finding(
                "RCV_LONG_DELAY", Severity.LOW,
                f"Hop {hop.index} took {hop.delay_seconds / 3600:.1f}h after the previous hop.",
                {"hop": hop.index, "delay_seconds": hop.delay_seconds},
            ))

    stamped = [hop for hop in h.hops if hop.timestamp]
    if h.date and stamped:
        first, last = stamped[0].timestamp, stamped[-1].timestamp
        if (h.date - last).total_seconds() > CLOCK_TOLERANCE_SECONDS:
            out.append(Finding(
                "HDR_DATE_AFTER_DELIVERY", Severity.MEDIUM,
                "Date header is later than the final delivery hop.",
                {"date": h.date.isoformat(), "last_hop": last.isoformat()},
            ))
        elif abs((first - h.date).total_seconds()) > DATE_SKEW_SECONDS:
            out.append(Finding(
                "HDR_DATE_SKEW", Severity.LOW,
                "Date header differs from the first Received hop by more than an hour.",
                {"date": h.date.isoformat(), "first_hop": first.isoformat()},
            ))
    return out


def _check_origin(h: HeaderAnalysis) -> list[Finding]:
    out = []
    origin = origin_hop(h)
    if origin:
        out.append(Finding(
            "RCV_ORIGIN_IP", Severity.INFO,
            f"Earliest public IP in the Received chain: {origin.from_ip} (hop {origin.index}). "
            "Hops below your own trusted relays can be forged.",
            {"ip": origin.from_ip, "host": origin.from_host, "hop": origin.index},
        ))
    if h.x_originating_ip:
        out.append(Finding("HDR_X_ORIGINATING_IP", Severity.INFO,
                           "X-Originating-IP header present (client IP reported by webmail).",
                           {"value": h.x_originating_ip}))
    return out


def _check_encoding(msg: EmailMessage, h: HeaderAnalysis) -> list[Finding]:
    out = []
    for name in ENCODED_HEADERS:
        for value in raw_headers(msg, name, decode=False):
            for m in _ENCODED_WORD_RE.finditer(value):
                problem = _encoded_word_problem(*m.groups())
                if problem:
                    out.append(Finding(
                        "HDR_ENCODED_WORD_ERROR", Severity.LOW,
                        f"{name} header has a malformed RFC 2047 encoded-word ({problem}).",
                        {"header": name, "encoded_word": m.group(0)[:200]},
                    ))
    out += invisible_char_findings("Subject", h.subject, prominent=True)
    out += invisible_char_findings("From display name", h.from_display_name, prominent=True)
    return out


def _encoded_word_problem(charset: str, encoding: str, data: str) -> str | None:
    charset = charset.split("*", 1)[0]  # RFC 2231 language suffix, e.g. utf-8*en
    if not is_text_charset(charset):
        return "unknown charset"
    if encoding.lower() == "b":
        try:
            base64.b64decode(data + "=" * (-len(data) % 4), validate=True)
        except (binascii.Error, ValueError):
            return "invalid base64"
    return None


def embedded_addresses(display_name: str | None) -> list[str]:
    if not display_name:
        return []
    return [m.group(0).lower() for m in _EMBEDDED_ADDR_RE.finditer(display_name)]


def origin_hop(h: HeaderAnalysis):
    """Oldest hop whose connecting IP is publicly routable."""
    return next((hop for hop in h.hops if hop.from_ip and hop.ip_is_private is False), None)
