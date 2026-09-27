"""Render reports as JSON or plain text."""

from __future__ import annotations

import json

from .models import Report
from .textcheck import safe_display

MAX_TEXT_URLS = 50
MAX_TEXT_MEMBERS = 20


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def to_text(report: Report) -> str:
    e, h = report.evidence, report.headers
    lines = [
        "=== Evidence ===",
        f"File:      {e.path}",
        f"Size:      {e.size} bytes",
        f"SHA-256:   {e.sha256}",
        f"MD5:       {e.md5}",
        f"Analyzed:  {e.analyzed_at.isoformat()} (tool v{e.tool_version})",
        "",
        "=== Summary ===",
        f"Subject:     {safe_display(h.subject) or '-'}",
        f"From:        {safe_display(h.from_display_name) + ' ' if h.from_display_name else ''}<{h.from_address}>",
        f"Return-Path: {h.return_path or '-'}",
        f"Reply-To:    {', '.join(h.reply_to) or '-'}",
        f"To:          {', '.join(h.to) or '-'}",
        f"Date:        {h.date.isoformat() if h.date else '-'}",
        f"Message-ID:  {h.message_id or '-'}",
        f"Mailer:      {h.x_mailer or '-'}",
        "",
        "=== Received chain (oldest first) ===",
    ]
    if not h.hops:
        lines.append("(none)")
    for hop in h.hops:
        ts = hop.timestamp.isoformat() if hop.timestamp else "?"
        delay = f"+{hop.delay_seconds:.0f}s" if hop.delay_seconds is not None else ""
        ip = f" [{hop.from_ip}{' private' if hop.ip_is_private else ''}]" if hop.from_ip else ""
        lines.append(f"{hop.index:>2}. {ts} {delay:>8}  {hop.from_host or '?'}{ip} -> {hop.by_host or '?'}"
                     f"{' (' + hop.protocol + ')' if hop.protocol else ''}")

    lines += ["", "=== Authentication ==="]
    if not h.auth_results:
        lines.append("(no Authentication-Results)")
    for r in h.auth_results:
        props = " ".join(f"{k}={v}" for k, v in r.properties.items())
        lines.append(f"{r.method:<6} {r.result:<9} {props}  [{r.authserv_id}]")

    b = report.body
    lines += ["", "=== MIME structure ==="]
    for part in b.parts:
        extra = []
        if part.charset:
            extra.append(part.charset)
        if part.transfer_encoding:
            extra.append(part.transfer_encoding)
        if part.filename:
            extra.append(f"filename={part.filename!r}")
        if part.is_attachment:
            extra.append("ATTACHMENT")
        size = f" {part.size}B" if part.sha256 else ""
        lines.append(f"{'  ' * part.depth}{part.path:<6} {part.content_type}{size}"
                     f"{'  [' + ', '.join(extra) + ']' if extra else ''}")

    lines += ["", f"=== URLs ({len(b.urls)}) ==="]
    for url in b.urls[:MAX_TEXT_URLS]:
        text = f'  text="{url.anchor_texts[0][:60]}"' if url.anchor_texts else ""
        lines.append(f"- {safe_display(url.url[:150])}  ({', '.join(url.sources)}){text}")
    if len(b.urls) > MAX_TEXT_URLS:
        lines.append(f"... {len(b.urls) - MAX_TEXT_URLS} more (use --json for all)")

    lines += ["", f"=== Attachments ({len(report.attachments)}) ==="]
    for att in report.attachments:
        name = safe_display(att.filename) if att.filename else "(no filename)"
        detected = att.detected_description or "unknown type"
        lines.append(f"- {att.part} '{name}' {att.size}B {att.content_type} -> {detected}"
                     f"{' [inline]' if att.inline else ''}")
        lines.append(f"    sha256={att.sha256} md5={att.md5}")
        if att.archive:
            a = att.archive
            lines.append(f"    archive: {len(a.members)} member(s), {a.total_uncompressed:,} bytes uncompressed"
                         f"{', ' + str(a.encrypted_members) + ' encrypted' if a.encrypted_members else ''}"
                         f"{', error: ' + a.error if a.error else ''}")
            for m in a.members[:MAX_TEXT_MEMBERS]:
                path = f"{m.container}/{m.name}" if m.container else m.name
                lines.append(f"      {safe_display(path)} ({m.size:,}B{', ' + m.detected_type if m.detected_type else ''}"
                             f"{', encrypted' if m.encrypted else ''})")
            if len(a.members) > MAX_TEXT_MEMBERS:
                lines.append(f"      ... {len(a.members) - MAX_TEXT_MEMBERS} more")
        if att.extracted_to:
            lines.append(f"    extracted: {att.extracted_to}")

    lines += ["", f"=== Findings ({len(report.findings)}) ==="]
    for f in report.findings:
        lines.append(f"[{f.severity.value.upper():<6}] {f.code}: {safe_display(f.message)}")
    return "\n".join(lines)
