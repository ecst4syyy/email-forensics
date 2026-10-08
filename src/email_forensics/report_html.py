"""Self-contained HTML report.

Safe to open: every value is HTML-escaped, URLs/domains/IPs in indicator lists are
defanged (hxxp://example[.]com), nothing is a link, no scripts run (CSP
``default-src 'none'``) and no external resource is ever loaded.
"""

from __future__ import annotations

import html
import re

from . import __version__
from .models import Report
from .textcheck import safe_display

_CSS = """
:root{--bg:#f7f7f8;--panel:#fff;--text:#1d1d1f;--muted:#5f6368;--border:#dadce0;--code:#f1f3f4;
--high:#b3261e;--high-bg:#fce8e6;--medium:#9a5b00;--medium-bg:#fef3e0;--low:#1a5fb4;--low-bg:#e8f0fe;
--info:#5f6368;--info-bg:#f1f3f4;--ok:#137333;--ok-bg:#e6f4ea}
@media (prefers-color-scheme:dark){:root{--bg:#121212;--panel:#1e1e1e;--text:#e8eaed;--muted:#9aa0a6;
--border:#3c4043;--code:#2a2a2a;--high:#f28b82;--high-bg:#3c1f1d;--medium:#fdd663;--medium-bg:#3a2e12;
--low:#8ab4f8;--low-bg:#1c2b41;--info:#9aa0a6;--info-bg:#2a2a2a;--ok:#81c995;--ok-bg:#1e3326}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.15rem;margin:0 0 10px}h3{font-size:1rem;margin:16px 0 6px}
section,.banner{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px 18px;margin:14px 0}
.banner{border-left:8px solid var(--info)}
.banner.malicious{border-left-color:var(--high)}.banner.suspicious{border-left-color:var(--medium)}
.banner.caution{border-left-color:var(--low)}.banner.clean{border-left-color:var(--ok)}
.score{font-size:2.4rem;font-weight:700;float:right;line-height:1}.muted{color:var(--muted)}
table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{text-align:left;vertical-align:top;
padding:6px 8px;border-bottom:1px solid var(--border)}
td.v,td.msg{overflow-wrap:anywhere}td.n{white-space:nowrap;color:var(--muted)}th{color:var(--muted);font-weight:600}
td.k{width:180px;color:var(--muted)}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:.85rem;background:var(--code);border-radius:4px}code{padding:1px 4px;overflow-wrap:break-word}
td>code:only-child{white-space:nowrap}td.v code{white-space:normal;overflow-wrap:anywhere}
pre{padding:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;max-height:420px}
.sev{display:inline-block;white-space:nowrap;min-width:64px;text-align:center;border-radius:12px;padding:1px 8px;font-size:.78rem;font-weight:600}
.sev.high{color:var(--high);background:var(--high-bg)}.sev.medium{color:var(--medium);background:var(--medium-bg)}
.sev.low{color:var(--low);background:var(--low-bg)}.sev.info{color:var(--info);background:var(--info-bg)}
.verdict{text-transform:uppercase;letter-spacing:.04em;font-weight:700}
details{margin:10px 0}summary{cursor:pointer;font-weight:600}.wrap{overflow-x:auto}
@media (max-width:640px){td.k{width:auto}.score{float:none;display:block;margin-bottom:6px}
table.stack,table.stack tbody{display:block}table.stack tr{display:block;padding:8px 0;border-bottom:1px solid var(--border)}
table.stack tr:first-child:has(th){display:none}table.stack td{display:inline-block;border:0;padding:2px 6px 2px 0}
table.stack td.msg{display:block}table.kv td{display:block;border:0;padding:2px 0}table.kv td.k{padding-top:8px}}
"""


_SCHEME_RE = re.compile(r"(h)(ttps?)(:|&#x3a;)//|(f)(tp)(:|&#x3a;)//", re.I)


def esc(value) -> str:
    """Escape for HTML and neutralise URL schemes everywhere (viewers auto-link URLs in text)."""
    text = html.escape(safe_display("" if value is None else str(value), keep_newlines=True), quote=True)
    return _SCHEME_RE.sub(lambda m: (m.group(1) + "xx" + m.group(2)[2:] + "://") if m.group(1)
                          else (m.group(4) + "x" + m.group(5)[1:] + "://"), text)


def defang(value: str | None) -> str:
    """hxxps://www[.]example[.]com/path -- unclickable, still readable."""
    if not value:
        return ""
    v = re.sub(r"^http", "hxxp", value, flags=re.I)
    v = re.sub(r"^ftp", "fxp", v, flags=re.I)
    m = re.match(r"^([a-z][a-z0-9+.-]*://)?([^/?#]*)(.*)$", v, re.I | re.S)
    if not m:
        return v.replace(".", "[.]")
    scheme, host, rest = m.groups()
    return (scheme or "") + host.replace(".", "[.]").replace("@", "[@]") + rest


def _sev(severity: str) -> str:
    return f'<span class="sev {esc(severity)}">{esc(severity)}</span>'


def _kv(rows) -> str:
    body = "".join(f'<tr><td class="k">{esc(k)}</td><td class="v">{v}</td></tr>' for k, v in rows if v not in (None, "", []))
    return f'<table class="kv">{body}</table>'


def html_head(title: str) -> str:
    """Document start with the stylesheet and the safety headers (no scripts, no remote loads)."""
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            f'<meta name="referrer" content="no-referrer"><title>{esc(title)}</title><style>{_CSS}</style></head><body>')


def render_html(reports: list[Report], title: str | None = None) -> str:
    title = title or (f"Email forensics: {reports[0].headers.subject or 'report'}" if len(reports) == 1
                      else f"Email forensics: {len(reports)} messages")
    parts = [html_head(title) + "<main>"]
    if len(reports) > 1:
        parts.append(_index(reports))
    for i, r in enumerate(reports, 1):
        parts.append(f'<article id="msg{i}">{_report(r, level=0)}</article>')
    parts.append(f'<p class="muted">Generated by email-forensics {esc(__version__)}. URLs and domains are defanged; '
                 'nothing in this report is clickable or loads remote content.</p></main></body></html>')
    return "".join(parts)


def _index(reports: list[Report]) -> str:
    rows = []
    for i, r in enumerate(reports, 1):
        a = r.assessment
        rows.append(f'<tr><td class="n">{i}</td><td class="n">{_sev_for_verdict(a.verdict if a else "clean")} '
                    f'{a.score if a else "-"}</td><td class="n">{esc(r.headers.date.strftime("%Y-%m-%d %H:%M") if r.headers.date else "-")}</td>'
                    f'<td class="msg">{esc(r.headers.from_address or "-")}</td><td class="msg">{esc(r.headers.subject or "-")}</td></tr>')
    return ('<section><h2>Messages</h2><div class="wrap"><table class="stack"><tr><th>#</th><th>Score</th><th>Date</th>'
            f'<th>From</th><th>Subject</th></tr>{"".join(rows)}</table></div></section>')


def _sev_for_verdict(verdict: str) -> str:
    sev = {"malicious": "high", "suspicious": "medium", "caution": "low"}.get(verdict, "info")
    return f'<span class="sev {sev}">{esc(verdict)}</span>'


def _report(r: Report, level: int) -> str:
    h, e, a = r.headers, r.evidence, r.assessment
    out = []
    verdict = a.verdict if a else "clean"
    out.append(f'<div class="banner {esc(verdict)}"><div class="score">{a.score if a else "-"}</div>'
               f'<div class="verdict">{esc(verdict)}</div><h1>{esc(h.subject or "(no subject)")}</h1>'
               f'<div class="muted">From {esc(h.from_display_name or "")} &lt;{esc(h.from_address or "?")}&gt; · '
               f'{esc(h.date.isoformat() if h.date else "no date")} · SHA-256 <code>{esc(e.sha256)}</code></div></div>')
    if a and a.reasons:
        items = "".join(f'<tr><td>{_sev(x.severity)}</td><td><code>{esc(x.code)}</code></td>'
                        f'<td class="msg">{esc(x.message)}</td><td class="n">+{x.points:g}</td></tr>' for x in a.reasons)
        out.append(f'<section><h2>Why this verdict</h2><div class="wrap"><table class="stack">{items}</table></div>'
                   + (f'<p class="muted">Minimum score set by {esc(a.floor)}.</p>' if a.floor else "") + '</section>')

    out.append('<section><h2>Evidence</h2>' + _kv([
        ("File", esc(e.path)), ("Format", esc(e.format + (" (MIME rebuilt/re-serialised)" if e.converted else ""))),
        ("Size", esc(f"{e.size:,} bytes")), ("SHA-256", f"<code>{esc(e.sha256)}</code>"),
        ("MD5", f"<code>{esc(e.md5)}</code>"), ("Analyzed", esc(f"{e.analyzed_at.isoformat()} (v{e.tool_version})")),
        ("Container", esc(e.container) + (f" <code>{esc(e.container_sha256)}</code>" if e.container_sha256 else "")
         if e.container else None),
        ("Notes", "<br>".join(esc(n) for n in e.notes)),
    ]) + '</section>')

    out.append('<section><h2>Headers</h2>' + _kv([
        ("From", esc(f"{h.from_display_name or ''} <{h.from_address or ''}>")), ("Reply-To", esc(", ".join(h.reply_to))),
        ("Return-Path", esc(h.return_path)), ("Sender", esc(h.sender)), ("To", esc(", ".join(h.to))),
        ("Cc", esc(", ".join(h.cc))), ("Date", esc(h.date.isoformat() if h.date else None)),
        ("Message-ID", esc(h.message_id)), ("Mailer", esc(h.x_mailer)), ("X-Originating-IP", esc(h.x_originating_ip)),
    ]))
    if h.hops:
        rows = "".join(f'<tr><td>{hop.index}</td><td>{esc(hop.timestamp.isoformat() if hop.timestamp else "?")}</td>'
                       f'<td>{esc("" if hop.delay_seconds is None else f"{hop.delay_seconds:+.0f}s")}</td>'
                       f'<td>{esc(hop.from_host)} <code>{esc(defang(hop.from_ip))}</code></td><td>{esc(hop.by_host)}</td>'
                       f'<td>{esc(hop.protocol)}</td></tr>' for hop in h.hops)
        out.append('<h3>Received chain (oldest first)</h3><div class="wrap"><table><tr><th>#</th><th>Time</th>'
                   f'<th>Delay</th><th>From</th><th>By</th><th>With</th></tr>{rows}</table></div>')
    if h.auth_results:
        rows = "".join(f'<tr><td>{esc(x.method)}</td><td>{esc(x.result)}</td><td>{esc(x.authserv_id)}</td>'
                       f'<td>{esc(" ".join(f"{k}={v}" for k, v in x.properties.items()))}</td></tr>' for x in h.auth_results)
        out.append('<h3>Authentication-Results (as recorded by receivers)</h3><div class="wrap"><table>'
                   f'<tr><th>Method</th><th>Result</th><th>Server</th><th>Details</th></tr>{rows}</table></div>')
    out.append('</section>')

    av = r.auth
    if av and (av.dkim or av.arc or av.spf or av.dmarc):
        rows = [f'<tr><td>DKIM</td><td>{esc(d.result)}</td><td>d={esc(d.domain)} s={esc(d.selector)} {esc(d.algorithm)}'
                f'</td><td>{esc(d.reason)}</td></tr>' for d in av.dkim]
        if av.arc:
            rows.append(f'<tr><td>ARC</td><td>{esc(av.arc.result)}</td><td>{av.arc.instances} set(s)</td>'
                        f'<td>{esc(av.arc.reason)}</td></tr>')
        if av.spf:
            rows.append(f'<tr><td>SPF</td><td>{esc(av.spf.result)}</td><td>{esc(av.spf.ip)} as {esc(av.spf.domain)}'
                        f'</td><td>{esc(av.spf.reason)} (IP from {esc(av.spf_ip_source)})</td></tr>')
        if av.dmarc:
            rows.append(f'<tr><td>DMARC</td><td>{esc(av.dmarc.result)}</td><td>{esc(av.dmarc.from_domain)} '
                        f'p={esc(av.dmarc.policy)}</td><td>{esc(av.dmarc.reason)}</td></tr>')
        mode = f"online via {esc(av.resolver)}" if av.online else "offline"
        out.append(f'<section><h2>Authentication re-verified ({mode})</h2><div class="wrap"><table>'
                   f'<tr><th>Check</th><th>Result</th><th>Subject</th><th>Detail</th></tr>{"".join(rows)}</table></div>'
                   + (f'<p class="muted">{len(av.dns_lookups)} DNS lookup(s) are recorded in the JSON report.</p>'
                      if av.dns_lookups else "") + '</section>')

    en = r.enrichment
    if en is not None and (en.records or en.skipped):
        rows = "".join(f'<tr><td>{esc(x.provider)}</td><td>{esc(x.kind)}</td><td><code>{esc(defang(x.value))}</code></td>'
                       f'<td class="msg">{esc(x.error or ", ".join(f"{k}={v}" for k, v in x.summary.items() if v not in (None, "", [], False)))}'
                       '</td></tr>' for x in en.records)
        skipped = "".join(f"<li>{esc(x)}</li>" for x in en.skipped)
        out.append(f'<section><h2>Enrichment</h2><div class="wrap"><table class="stack"><tr><th>Provider</th><th>Kind</th>'
                   f'<th>Indicator</th><th>Result</th></tr>{rows}</table></div>'
                   + (f'<p class="muted">Skipped:</p><ul class="muted">{skipped}</ul>' if skipped else "") + '</section>')

    if r.body.urls:
        rows = "".join(f'<tr><td><code>{esc(defang(u.url))}</code></td><td>{esc(", ".join(u.sources))}</td>'
                       f'<td>{esc(u.anchor_texts[0] if u.anchor_texts else "")}</td></tr>' for u in r.body.urls[:500])
        out.append(f'<section><h2>Links ({len(r.body.urls)})</h2><div class="wrap"><table><tr><th>URL (defanged)</th>'
                   f'<th>Found in</th><th>Link text</th></tr>{rows}</table></div></section>')

    if r.attachments:
        blocks = []
        for att in r.attachments:
            rows = [("Declared type", esc(att.content_type)), ("Detected type", esc(att.detected_description)),
                    ("Size", esc(f"{att.size:,} bytes")), ("SHA-256", f"<code>{esc(att.sha256)}</code>"),
                    ("SHA-1", f"<code>{esc(att.sha1)}</code>"), ("MD5", f"<code>{esc(att.md5)}</code>")]
            if att.archive:
                members = "<br>".join(esc(f"{m.container + '/' if m.container else ''}{m.name} ({m.size:,}B"
                                          f"{', ' + m.detected_type if m.detected_type else ''}"
                                          f"{', encrypted' if m.encrypted else ''})") for m in att.archive.members[:50])
                rows.append(("Archive", members))
            if att.urls:
                rows.append(("Links", "<br>".join(f"<code>{esc(defang(u.url))}</code>" for u in att.urls[:50])))
            rows += _payload_rows(att.payload)
            blocks.append(f'<h3>{esc(att.filename or "(no filename)")} <span class="muted">part {esc(att.part)}'
                          f'{" · inline" if att.inline else ""}</span></h3>{_kv(rows)}')
        out.append(f'<section><h2>Attachments ({len(r.attachments)})</h2>{"".join(blocks)}</section>')

    ident = r.identity
    out.append('<section><h2>Sender identity</h2>' + _kv([
        ("Mailer", esc(f"{ident.mailer or '-'}" + (f" ({ident.mailer_name}, {ident.mailer_category})"
                                                   if ident.mailer_name else ""))),
        ("PHP script", esc(ident.php_script)), ("Recipient domains", esc(", ".join(ident.recipient_domains))),
        *((f"{p} verdict", esc(" ".join(f"{k}={v}" for k, v in v.items()))) for p, v in ident.provider_verdicts.items()),
    ]) + '</section>')

    rows = "".join(f'<tr><td>{_sev(f.severity.value)}</td><td><code>{esc(f.code)}</code></td>'
                   f'<td class="msg">{esc(f.message)}</td></tr>' for f in r.findings)
    out.append(f'<section><h2>All findings ({len(r.findings)})</h2><div class="wrap"><table class="stack">{rows}</table>'
               '</div></section>')

    if r.yara:
        rows = "".join(f'<tr><td><code>{esc(m.namespace)}:{esc(m.rule)}</code></td><td class="msg">{esc(m.target)}</td>'
                       f'<td class="msg">{esc(", ".join(m.strings[:6]))}</td></tr>' for m in r.yara[:100])
        out.append(f'<section><h2>YARA matches ({len(r.yara)})</h2><div class="wrap"><table class="stack">{rows}</table>'
                   '</div></section>')
    if r.suppressed:
        rows = "".join(f'<tr><td><code>{esc(x.code)}</code></td><td>{esc(x.rule)}</td><td class="msg">{esc(x.message)}</td></tr>'
                       for x in r.suppressed)
        out.append(f'<section><h2>Suppressed by custom rules ({len(r.suppressed)})</h2><div class="wrap">'
                   f'<table class="stack">{rows}</table></div></section>')

    if r.body.text_bodies:
        previews = "".join(f'<h3>Part {esc(tb.part)} <span class="muted">{esc(tb.content_type)}, {tb.length:,} chars'
                           f'</span></h3><pre>{esc(tb.preview[:3000])}</pre>' for tb in r.body.text_bodies)
        out.append(f'<section><details><summary>Message text (as plain text, links not active)</summary>{previews}'
                   '</details></section>')
    mime = "\n".join(f"{'  ' * p.depth}{p.path} {p.content_type}{' ' + repr(p.filename) if p.filename else ''}"
                     for p in r.body.parts)
    out.append(f'<section><details><summary>MIME structure</summary><pre>{esc(mime)}</pre></details></section>')

    for n in r.nested:
        out.append(f'<section><details{" open" if level == 0 else ""}><summary>Attached message {esc(n.part)}'
                   f'{" — " + esc(n.filename) if n.filename else ""}</summary>{_report(n.report, level + 1)}'
                   '</details></section>')
    return "".join(out)


def _payload_rows(pa) -> list[tuple[str, str]]:
    if pa is None:
        return []
    rows = []
    o = pa.office
    if o:
        if o.metadata:
            rows.append(("Document metadata", esc(", ".join(f"{k}={v}" for k, v in o.metadata.items()))))
        for m in o.vba:
            tags = ", ".join(m.autoexec + [s.split(":")[0] for s in m.suspicious])
            rows.append((f"VBA {m.name}", (f"{esc(tags)}<pre>{esc(m.preview[:2000])}</pre>")))
        if o.dde:
            rows.append(("DDE", "<br>".join(esc(d) for d in o.dde)))
        if o.xlm_macros:
            rows.append(("XLM macros", "<br>".join(esc(x) for x in o.xlm_macros[:10])))
        if o.embedded:
            rows.append(("Embedded", "<br>".join(esc(f"{x.name or x.source} ({x.size:,}B, {x.detected_type or '?'}) "
                                                     f"{x.sha256}") for x in o.embedded)))
        if o.external:
            rows.append(("External", "<br>".join(f"{esc(x['type'])}: <code>{esc(defang(x['target']))}</code>"
                                                 for x in o.external[:20])))
    if pa.pdf:
        p = pa.pdf
        rows.append(("PDF keywords", esc(", ".join(f"/{k}={v}" for k, v in p.keywords.items()))))
        if p.javascript:
            rows.append(("PDF JavaScript", "".join(f"<pre>{esc(j)}</pre>" for j in p.javascript[:3])))
        if p.launch:
            rows.append(("PDF Launch", esc(", ".join(p.launch))))
    if pa.lnk:
        lk = pa.lnk
        rows.append(("Shortcut", esc(f"{lk.target or lk.env_target or '?'} {lk.arguments or ''}".strip())))
        if lk.machine_id:
            rows.append(("Created on machine", esc(lk.machine_id)))
    if pa.script:
        rows += [(f"Script: {k}", esc(", ".join(v))) for k, v in pa.script.indicators.items()]
        rows += [("Decoded command", f"<pre>{esc(c)}</pre>") for c in pa.script.decoded_commands[:2]]
    if pa.embedded:
        rows.append(("Embedded", "<br>".join(esc(f"{x.source} ({x.size:,}B, {x.detected_type or '?'})")
                                             for x in pa.embedded)))
    return rows
