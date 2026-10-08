"""Indicator-of-compromise extraction and export (CSV, STIX 2.1, MISP).

Every indicator keeps its role (sender, reply-to, link, origin IP, attachment, ...)
and the verdict of the message it came from, because a clean newsletter's domains
are not indicators of anything: consumers should filter on `verdict`.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from . import __version__
from .domains import domain_of
from .models import Report

_NS = uuid.UUID("6b1b1e8e-3f6f-4c5e-9d07-6a2f0b9c1d11")  # namespace for deterministic STIX ids


@dataclass(frozen=True)
class Indicator:
    type: str  # email-addr, domain, ipv4, ipv6, url, sha256, sha1, md5, filename, subject, message-id
    value: str
    role: str  # where it came from, e.g. "from", "reply-to", "link", "origin-ip", "attachment"
    evidence_sha256: str
    verdict: str
    context: str = ""


def _clean(text: str | None) -> str:
    """Lone surrogates (undecodable input bytes) become visible \\udcXX escapes."""
    return (text or "").encode("utf-8", "backslashreplace").decode("utf-8")


def _ip_type(value: str) -> str | None:
    try:
        return "ipv4" if ipaddress.ip_address(value).version == 4 else "ipv6"
    except ValueError:
        return None


def extract_iocs(report: Report, include_nested: bool = True) -> list[Indicator]:
    seen: dict[tuple[str, str, str], Indicator] = {}

    def add(itype: str, value: str | None, role: str, report: Report, context: str = "") -> None:
        if not value:
            return
        # Undecodable bytes surface as lone surrogates; make them visible escapes so every
        # export (UTF-8 files, JSON, STIX ids) can carry the value.
        value, context = _clean(value.strip()), _clean(context)
        verdict = report.assessment.verdict if report.assessment else "unknown"
        key = (itype, value.lower() if itype not in ("url", "filename", "subject") else value, role)
        if key not in seen:
            seen[key] = Indicator(itype, value, role, report.evidence.sha256, verdict, context[:200])

    def walk(r: Report) -> None:
        h = r.headers
        for role, addr in [("from", h.from_address), ("return-path", h.return_path), ("sender", h.sender),
                           *(("reply-to", x) for x in h.reply_to)]:
            add("email-addr", addr, role, r)
            add("domain", domain_of(addr), f"{role}-domain", r)
        add("subject", h.subject, "subject", r)
        add("message-id", (h.message_id or "").strip(), "message-id", r)
        for hop in h.hops:
            if hop.from_ip and hop.ip_is_private is False:
                add(_ip_type(hop.from_ip) or "ipv4", hop.from_ip, "received-ip", r, f"hop {hop.index} from {hop.from_host}")
        if h.x_originating_ip:
            ip = h.x_originating_ip.strip("[] ")
            if _ip_type(ip):
                add(_ip_type(ip), ip, "x-originating-ip", r)

        urls = [(u, "link") for u in r.body.urls] + [(u, "attachment-link") for a in r.attachments for u in a.urls]
        for u, role in urls:
            if u.scheme in ("http", "https", "ftp", ""):
                add("url", u.url, role, r, ", ".join(u.sources))
            if u.host:
                t = _ip_type(u.host.strip("[]"))
                add(t or "domain", u.host.strip("[]"), f"{role}-host", r)

        for a in r.attachments:
            ctx = f"{a.filename or 'part ' + a.part} ({a.detected_type or a.content_type})"
            add("filename", a.filename, "attachment", r, ctx)
            for kind in ("sha256", "sha1", "md5"):
                add(kind, getattr(a, kind), "attachment", r, ctx)
            if a.archive:
                for m in a.archive.members:
                    if m.sha256:
                        name = f"{m.container + '/' if m.container else ''}{m.name}"
                        add("sha256", m.sha256, "archive-member", r, f"{name} in {a.filename}")
                        add("filename", name.rsplit("/", 1)[-1], "archive-member", r, f"in {a.filename}")
            pa = a.payload
            embedded = (pa.office.embedded if pa and pa.office else []) + (pa.pdf.embedded if pa and pa.pdf else []) \
                + (pa.embedded if pa else [])
            for e in embedded:
                if e.sha256:
                    add("sha256", e.sha256, "embedded-file", r, f"{e.name or e.source} in {a.filename}")
                if e.name:
                    add("filename", e.name, "embedded-file", r, f"in {a.filename}")
            if pa and pa.script:
                for ip in pa.script.ips:
                    add(_ip_type(ip) or "ipv4", ip, "script-ip", r, f"in {a.filename}")
        if include_nested:
            for n in r.nested:
                walk(n.report)

    walk(report)
    return list(seen.values())


# --------------------------------------------------------------------------- CSV

def to_csv(indicators: list[Indicator]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(Indicator.__dataclass_fields__))
    writer.writeheader()
    for ind in indicators:
        writer.writerow(asdict(ind))
    return buf.getvalue()


# --------------------------------------------------------------------------- STIX 2.1

_STIX_PATTERNS = {
    "url": "url:value", "domain": "domain-name:value", "ipv4": "ipv4-addr:value", "ipv6": "ipv6-addr:value",
    "email-addr": "email-addr:value", "sha256": "file:hashes.'SHA-256'", "sha1": "file:hashes.'SHA-1'",
    "md5": "file:hashes.MD5", "filename": "file:name", "subject": "email-message:subject",
}


def _stix_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _stix_id(kind: str, *parts: str) -> str:
    name = "|".join(parts).encode("utf-8", "surrogatepass").decode("utf-8", "replace")
    return f"{kind}--{uuid.uuid5(_NS, name)}"


def to_stix(indicators: list[Indicator], reports: list[Report]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity_id = _stix_id("identity", "email-forensics")
    objects: list[dict] = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id, "created": now, "modified": now,
        "name": f"email-forensics {__version__}", "identity_class": "system",
    }]
    ids = []
    for ind in indicators:
        path = _STIX_PATTERNS.get(ind.type)
        if not path:
            continue
        sid = _stix_id("indicator", ind.type, ind.value, ind.role, ind.evidence_sha256)
        ids.append(sid)
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": sid, "created": now, "modified": now,
            "created_by_ref": identity_id, "name": f"{ind.role}: {ind.value}"[:250],
            "description": f"{ind.type} seen as {ind.role} in a message assessed as {ind.verdict}"
                           + (f" ({ind.context})" if ind.context else ""),
            "indicator_types": ["malicious-activity"] if ind.verdict in ("malicious", "suspicious") else ["anomalous-activity"],
            "pattern": f"[{path} = '{_stix_escape(ind.value)}']", "pattern_type": "stix", "valid_from": now,
            "labels": [ind.verdict, ind.role],
            "external_references": [{"source_name": "evidence-sha256", "external_id": ind.evidence_sha256}],
        })
    for r in reports:
        objects.append({
            "type": "report", "spec_version": "2.1", "id": _stix_id("report", r.evidence.sha256), "created": now,
            "modified": now, "created_by_ref": identity_id, "name": _clean(r.headers.subject or "email")[:250],
            "description": f"Email {r.evidence.sha256} assessed as {r.assessment.verdict if r.assessment else '?'} "
                           f"(score {r.assessment.score if r.assessment else '?'})",
            "report_types": ["threat-report"], "published": now,
            "object_refs": [i for i in ids] or [identity_id],
        })
    bundle = {"type": "bundle", "id": _stix_id("bundle", *(r.evidence.sha256 for r in reports)), "objects": objects}
    return json.dumps(bundle, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- MISP

_MISP_TYPES = {
    ("email-addr", "from"): ("email-src", "Payload delivery"), ("email-addr", "return-path"): ("email-src", "Payload delivery"),
    ("email-addr", "sender"): ("email-src", "Payload delivery"), ("email-addr", "reply-to"): ("email-reply-to", "Payload delivery"),
    ("subject", "subject"): ("email-subject", "Payload delivery"), ("message-id", "message-id"): ("email-message-id", "Payload delivery"),
    ("filename", None): ("email-attachment", "Payload delivery"), ("url", None): ("url", "Network activity"),
    ("domain", None): ("domain", "Network activity"), ("ipv4", None): ("ip-src", "Network activity"),
    ("ipv6", None): ("ip-src", "Network activity"), ("sha256", None): ("sha256", "Payload delivery"),
    ("sha1", None): ("sha1", "Payload delivery"), ("md5", None): ("md5", "Payload delivery"),
}


def to_misp(indicators: list[Indicator], reports: list[Report]) -> str:
    worst = max((r.assessment.score for r in reports if r.assessment), default=0)
    threat_level = "1" if worst >= 70 else "2" if worst >= 35 else "3"
    attributes = []
    for ind in indicators:
        mtype = _MISP_TYPES.get((ind.type, ind.role)) or _MISP_TYPES.get((ind.type, None))
        if not mtype:
            continue
        if ind.type in ("ipv4", "ipv6") and ind.role.endswith("-host"):
            mtype = ("ip-dst", "Network activity")
        attributes.append({
            "type": mtype[0], "category": mtype[1], "value": ind.value,
            "to_ids": ind.verdict in ("malicious", "suspicious") and ind.type not in ("subject", "message-id", "filename"),
            "comment": f"{ind.role}; message {ind.verdict}" + (f"; {ind.context}" if ind.context else ""),
            "distribution": "5",
        })
    subject = _clean(reports[0].headers.subject) if len(reports) == 1 else f"{len(reports)} emails"
    event = {"Event": {
        "info": f"Email forensics: {subject or 'email'}"[:250],
        "date": datetime.now(timezone.utc).date().isoformat(), "threat_level_id": threat_level,
        "analysis": "2", "distribution": "0", "Attribute": attributes,
        "Tag": [{"name": f"email-forensics:verdict=\"{r.assessment.verdict}\""} for r in reports if r.assessment][:1],
    }}
    return json.dumps(event, indent=2, ensure_ascii=False)
