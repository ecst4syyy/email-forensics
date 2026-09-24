"""Render reports as JSON or plain text."""

from __future__ import annotations

import json

from .models import Report


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
        f"Subject:     {h.subject or '-'}",
        f"From:        {h.from_display_name + ' ' if h.from_display_name else ''}<{h.from_address}>",
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

    lines += ["", f"=== Findings ({len(report.findings)}) ==="]
    for f in report.findings:
        lines.append(f"[{f.severity.value.upper():<6}] {f.code}: {f.message}")
    return "\n".join(lines)
