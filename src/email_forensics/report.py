"""Render reports as JSON or plain text."""

from __future__ import annotations

import json

from .models import Report
from .textcheck import safe_display

MAX_TEXT_URLS = 50
MAX_TEXT_MEMBERS = 20


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def to_text(report: Report, indent: str = "") -> str:
    text = _to_text(report)
    for n in report.nested:
        title = f"=== Attached message {n.part}{' ' + repr(safe_display(n.filename)) if n.filename else ''} ==="
        text += "\n\n" + title + "\n" + to_text(n.report, "    ")
    return "\n".join(indent + line if line else line for line in text.splitlines())


def _to_text(report: Report) -> str:
    e, h = report.evidence, report.headers
    a = report.assessment
    lines = []
    if a is not None:
        lines += [f"=== Verdict: {a.verdict.upper()} (score {a.score}/100) ==="]
        lines += [f"  +{r.points:>4g}  {r.code}: {safe_display(r.message)[:150]}" for r in a.reasons[:5]]
        if a.floor:
            lines.append(f"  (minimum score set by {a.floor})")
        lines.append("")
    lines += [
        "=== Evidence ===",
        f"File:      {safe_display(e.path)}",
        f"Format:    {e.format}{' (MIME rebuilt/re-serialised for analysis)' if e.converted else ''}",
        f"Size:      {e.size} bytes",
        f"SHA-256:   {e.sha256}",
        f"MD5:       {e.md5}",
        f"Analyzed:  {e.analyzed_at.isoformat()} (tool v{e.tool_version})",
        *([f"Container: {safe_display(e.container)} (sha256 {e.container_sha256})"] if e.container else []),
        *[f"Note:      {safe_display(n)}" for n in e.notes],
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

    if report.msg is not None:
        m = report.msg
        lines += ["", "=== Outlook .msg properties ==="]
        for label, value in (("Message class", m.message_class), ("Submitted", m.submit_time),
                             ("Delivered", m.delivery_time), ("Created", m.creation_time),
                             ("Last modified", m.last_modified_time), ("Modified by", m.last_modified_by),
                             ("Sender SMTP", m.sender_smtp)):
            if value:
                lines.append(f"{label + ':':<15}{safe_display(value)}")
        lines.append(f"{'Transport hdrs:':<15}{'yes' if m.has_transport_headers else 'NO (headers rebuilt from properties)'}")

    ident = report.identity
    lines += ["", "=== Sender identity ==="]
    mailer = f"{safe_display(ident.mailer)}" if ident.mailer else "-"
    if ident.mailer_name:
        mailer += f"  -> {ident.mailer_name} [{ident.mailer_category}]"
    lines.append(f"Mailer:            {mailer}")
    if ident.php_script:
        lines.append(f"PHP script:        {safe_display(ident.php_script)}")
    lines.append(f"Recipient domains: {', '.join(ident.recipient_domains) or '-'}")
    lines.append(f"Lookalike check:   {ident.protected_domain_count} protected domains, "
                 f"sender addresses + {ident.checked_hosts} URL host(s)")
    for provider, verdict in ident.provider_verdicts.items():
        lines.append(f"{provider + ':':<19}" + " ".join(f"{k}={safe_display(v)}" for k, v in verdict.items()))

    av = report.auth
    if av is not None:
        lines += ["", f"=== Authentication re-verified ({'online via ' + av.resolver if av.online else 'offline'}) ==="]
        for d in av.dkim:
            body = {True: "body ok", False: "BODY MODIFIED", None: "body ?"}[d.body_hash_ok]
            lines.append(f"dkim   {d.result:<9} d={d.domain} s={d.selector} {d.algorithm} {body}"
                         f"{f' key={d.key_bits}b' if d.key_bits else ''}  ({d.reason})")
        if not av.dkim:
            lines.append("dkim   (no signatures)")
        if av.arc:
            lines.append(f"arc    {av.arc.result:<9} {av.arc.instances} instance(s)  ({av.arc.reason})")
        if av.spf:
            lines.append(f"spf    {av.spf.result:<9} ip={av.spf.ip} [{av.spf_ip_source}] domain={av.spf.domain}"
                         f"  ({av.spf.reason})")
        if av.dmarc:
            lines.append(f"dmarc  {av.dmarc.result:<9} from={av.dmarc.from_domain} policy={av.dmarc.policy}"
                         f"  ({av.dmarc.reason})")
        if av.dns_lookups:
            lines.append(f"dns    {len(av.dns_lookups)} lookup(s) recorded in the JSON report")

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
        lines += _payload_lines(att.payload)
        if att.extracted_to:
            lines.append(f"    extracted: {att.extracted_to}")

    lines += ["", f"=== Findings ({len(report.findings)}) ==="]
    for f in report.findings:
        lines.append(f"[{f.severity.value.upper():<6}] {f.code}: {safe_display(f.message)}")
    return "\n".join(lines)


def _payload_lines(pa) -> list[str]:
    if pa is None:
        return []
    out = []
    o = pa.office
    if o:
        if o.metadata:
            out.append("    metadata: " + ", ".join(f"{k}={safe_display(v)}" for k, v in list(o.metadata.items())[:6]))
        for m in o.vba:
            tags = (["autoexec: " + ", ".join(m.autoexec)] if m.autoexec else []) + \
                   ([f"{len(m.suspicious)} suspicious"] if m.suspicious else []) + (["STOMPED"] if m.stomped else [])
            out.append(f"    vba {safe_display(m.name)} ({m.code_bytes}B){'  [' + '; '.join(tags) + ']' if tags else ''}")
        if o.xlm_macros:
            out.append(f"    xlm macros: {safe_display(o.xlm_macros[0][:80])}")
        for d in o.dde[:3]:
            out.append(f"    dde: {safe_display(d[:100])}")
        for e in o.embedded[:5]:
            out.append(f"    embedded: {safe_display(e.name or e.source)} ({e.size}B, {e.detected_type or 'unknown'})")
        for e in o.external[:5]:
            out.append(f"    external {e['type']}: {safe_display(e['target'][:100])}")
        if o.rtf_object_classes:
            out.append(f"    rtf objects: {', '.join(o.rtf_object_classes)}")
    if pa.pdf:
        p = pa.pdf
        risky = {k: v for k, v in p.keywords.items() if k not in ("Page", "Annot")}
        out.append(f"    pdf {p.version or '?'}: {p.streams} streams, keywords "
                   + (", ".join(f"/{k}={v}" for k, v in risky.items()) or "none"))
        for u in p.uris[:5]:
            out.append(f"    pdf link: {safe_display(u[:120])}")
        for j in p.javascript[:2]:
            out.append(f"    pdf js: {safe_display(j[:100])}")
    if pa.lnk:
        lk = pa.lnk
        out.append(f"    lnk target: {safe_display(lk.target or lk.env_target or lk.relative_path or '?')}")
        if lk.arguments:
            out.append(f"    lnk args: {safe_display(lk.arguments.strip()[:160])}")
        if lk.machine_id:
            out.append(f"    lnk created on: {safe_display(lk.machine_id)}")
    if pa.script:
        for k, v in pa.script.indicators.items():
            out.append(f"    script {k}: {safe_display(', '.join(v[:4]))}")
        for c in pa.script.decoded_commands[:2]:
            out.append(f"    decoded: {safe_display(c[:160])}")
    for e in pa.embedded[:5]:
        out.append(f"    embedded: {e.source} ({e.size}B, {e.detected_type or 'unknown'})")
    return out


def summary_row(report: Report) -> dict:
    counts = {s: 0 for s in ("high", "medium", "low")}
    for f in report.findings:
        if f.severity.value in counts:
            counts[f.severity.value] += 1
    h = report.headers
    a = report.assessment
    return {
        "score": a.score if a else None, "verdict": a.verdict if a else None,
        "evidence": report.evidence.path, "sha256": report.evidence.sha256, "date": h.date.isoformat() if h.date else None,
        "from": h.from_address, "subject": h.subject, "attachments": len(report.attachments),
        "nested": len(report.nested), **counts,
        "top": [f.code for f in report.findings if f.severity.value == "high"][:5],
    }


def to_summary(reports: list[Report]) -> str:
    lines = [f"{'#':>4}  {'SCORE':>5} {'VERDICT':<10}  {'HIGH':>4} {'MED':>4}  {'DATE':<16}  {'FROM':<32}  SUBJECT"]
    for i, r in enumerate(reports, 1):
        row = summary_row(r)
        date = (row["date"] or "-")[:16]
        lines.append(f"{i:>4}  {row['score'] if row['score'] is not None else '-':>5} {row['verdict'] or '-':<10}  "
                     f"{row['high']:>4} {row['medium']:>4}  {date:<16}  "
                     f"{safe_display(row['from'] or '-')[:32]:<32}  {safe_display(row['subject'] or '-')[:60]}")
    verdicts = [r.assessment.verdict for r in reports if r.assessment]
    counts = ", ".join(f"{verdicts.count(v)} {v}" for v in ("malicious", "suspicious", "caution", "clean") if verdicts.count(v))
    lines.append(f"\n{len(reports)} message(s): {counts or 'none assessed'}")
    return "\n".join(lines)
