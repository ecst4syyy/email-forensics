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
