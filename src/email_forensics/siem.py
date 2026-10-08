"""SIEM-friendly output: JSON Lines events and ArcSight CEF.

One event per analysed message (nested messages included), with the verdict,
score, the top reasons, key header fields and indicators, so detections can be
searched and alerted on in Splunk, Elastic, Sentinel, QRadar or ArcSight.
"""

from __future__ import annotations

import json
from datetime import datetime

from . import __version__
from .iocs import extract_iocs
from .models import Report


def event(report: Report, parent: str | None = None) -> dict:
    h, a = report.headers, report.assessment
    iocs = extract_iocs(report, include_nested=False)
    return {
        "event_type": "email_forensics.analysis",
        "tool": f"email-forensics/{__version__}",
        "analyzed_at": report.evidence.analyzed_at.isoformat(),
        "evidence": {"path": report.evidence.path, "sha256": report.evidence.sha256, "format": report.evidence.format,
                     "container_sha256": report.evidence.container_sha256, "parent_sha256": parent},
        "verdict": a.verdict if a else None, "score": a.score if a else None,
        "reasons": [{"code": r.code, "points": r.points, "message": r.message} for r in (a.reasons if a else [])[:5]],
        "email": {"subject": h.subject, "from": h.from_address, "from_display_name": h.from_display_name,
                  "reply_to": h.reply_to, "return_path": h.return_path, "to": h.to, "cc": h.cc,
                  "date": h.date.isoformat() if h.date else None, "message_id": h.message_id},
        "findings": sorted({f.code for f in report.findings}),
        "attachments": [{"filename": x.filename, "sha256": x.sha256, "type": x.detected_type} for x in report.attachments],
        "indicators": [{"type": i.type, "value": i.value, "role": i.role} for i in iocs],
    }


def events(report: Report, parent: str | None = None) -> list[dict]:
    out = [event(report, parent)]
    for n in report.nested:
        out += events(n.report, report.evidence.sha256)
    return out


def to_jsonl(reports: list[Report]) -> str:
    return "\n".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "backslashreplace")
                     .decode("utf-8") for r in reports for e in events(r))


def _cef_escape(value: str, header: bool = False) -> str:
    value = str(value).replace("\\", "\\\\").replace("\r", " ").replace("\n", " ")
    return value.replace("|", "\\|") if header else value.replace("=", "\\=")


def to_cef(reports: list[Report]) -> str:
    lines = []
    for r in reports:
        for e in events(r):
            score = e["score"] or 0
            ext = {
                "rt": int(datetime.fromisoformat(e["analyzed_at"]).timestamp() * 1000),
                "fname": e["evidence"]["path"], "fileHash": e["evidence"]["sha256"],
                "suser": e["email"]["from"] or "", "duser": ",".join(e["email"]["to"])[:1000],
                "msg": e["email"]["subject"] or "", "cs1Label": "verdict", "cs1": e["verdict"] or "",
                "cs2Label": "findings", "cs2": ",".join(e["findings"])[:2000],
                "cs3Label": "reply_to", "cs3": ",".join(e["email"]["reply_to"]),
                "cn1Label": "score", "cn1": score,
            }
            name = f"{(e['verdict'] or 'unknown').upper()} email: {e['email']['subject'] or '(no subject)'}"[:200]
            lines.append("CEF:0|email-forensics|email-forensics|" + _cef_escape(__version__, True) + "|"
                         + _cef_escape(e["verdict"] or "unknown", True) + "|" + _cef_escape(name, True) + "|"
                         + str(min(10, round(score / 10))) + "|"
                         + " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items()))
    return "\n".join(lines).encode("utf-8", "backslashreplace").decode("utf-8")
