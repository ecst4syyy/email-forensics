"""Body analysis: MIME structure, text/HTML bodies, URLs, and the findings they produce."""

from __future__ import annotations

from email.message import Message

from .domains import org_domain
from .html_analysis import analyze_html
from .mime import decode_text, walk_mime
from .models import BodyAnalysis, Finding, HtmlAnalysis, Link, Severity, TextBody
from .textcheck import invisible_char_findings
from .urls import collect_urls, extract_text_urls, link_text_host, split_url, url_findings

TEXT_PREVIEW_CHARS = 4000
MAX_EXAMPLES = 10


def analyze_body(msg: Message) -> tuple[BodyAnalysis, list[Finding]]:
    tree = walk_mime(msg)
    body = BodyAnalysis(parts=tree.parts)
    findings = list(tree.findings)
    links: list[Link] = []

    for leaf in tree.leaves:
        info = leaf.info
        if info.is_attachment or info.content_type not in ("text/plain", "text/html"):
            continue
        text, problem = decode_text(leaf.payload, info.charset)
        if problem:
            findings.append(Finding("BODY_CHARSET_PROBLEM", Severity.LOW,
                                    f"Part {info.path}: {problem}.", {"part": info.path}))

        if info.content_type == "text/html":
            html, visible = analyze_html(text, info.path)
            body.html.append(html)
            links += html.links
            # URLs written as anchor text are what the reader *sees*, not a destination.
            anchor_texts = {l.text for l in html.links if l.source == "a" and l.text}
            links += [l for l in extract_text_urls(visible, info.path) if l.url not in anchor_texts]
            text = visible
            findings += _html_findings(html)
        else:
            links += extract_text_urls(text, info.path)

        body.text_bodies.append(TextBody(
            part=info.path, content_type=info.content_type, length=len(text),
            preview=text[:TEXT_PREVIEW_CHARS],
        ))
        findings += invisible_char_findings(f"Body part {info.path}", text, prominent=False)

    body.urls = collect_urls(links)
    for url in body.urls:
        findings += url_findings(url)
    findings += _link_text_findings(links)
    findings += _structure_findings(body)
    return body, findings


def _html_findings(h: HtmlAnalysis) -> list[Finding]:
    out = []
    part = {"part": h.part}
    if h.scripts:
        out.append(Finding("HTML_SCRIPT", Severity.MEDIUM,
                           f"HTML part {h.part} contains {h.scripts} <script> element(s); mail clients "
                           "block them, so their presence suggests a phishing page or HTML attachment lure.",
                           {**part, "count": h.scripts}))
    if h.event_handlers:
        out.append(Finding("HTML_EVENT_HANDLERS", Severity.MEDIUM,
                           f"HTML part {h.part} uses JavaScript event handler attributes.",
                           {**part, "handlers": sorted(set(h.event_handlers))[:MAX_EXAMPLES]}))
    for form in h.forms:
        if "password" in form.input_types:
            out.append(Finding("HTML_CREDENTIAL_FORM", Severity.HIGH,
                               f"HTML part {h.part} contains a form with a password field.",
                               {**part, "action": form.action, "inputs": form.input_types}))
        elif form.input_types or form.action:
            out.append(Finding("HTML_FORM", Severity.MEDIUM,
                               f"HTML part {h.part} contains a form that submits data"
                               f"{' to ' + form.action if form.action else ''}.",
                               {**part, "action": form.action, "inputs": form.input_types}))
    if h.embedded_frames:
        out.append(Finding("HTML_EMBEDDED_FRAME", Severity.MEDIUM,
                           f"HTML part {h.part} embeds frames/objects.",
                           {**part, "sources": h.embedded_frames[:MAX_EXAMPLES]}))
    if h.meta_refresh:
        out.append(Finding("HTML_META_REFRESH", Severity.MEDIUM,
                           f"HTML part {h.part} auto-redirects via meta refresh to {h.meta_refresh}.",
                           {**part, "url": h.meta_refresh}))
    if h.base_href:
        out.append(Finding("HTML_BASE_HREF", Severity.LOW,
                           "HTML sets <base href>, which changes where relative links point "
                           "and can hide the real destination from scanners.",
                           {**part, "base_href": h.base_href}))
    if h.hidden_text:
        words = sum(len(t.split()) for t in h.hidden_text)
        out.append(Finding("HTML_HIDDEN_TEXT", Severity.MEDIUM if words >= 20 else Severity.LOW,
                           f"HTML part {h.part} contains ~{words} words of CSS-hidden text "
                           "(used to poison spam filters or smuggle content).",
                           {**part, "snippets": h.hidden_text[:MAX_EXAMPLES]}))
    if h.tracking_pixels:
        out.append(Finding("HTML_TRACKING_PIXEL", Severity.INFO,
                           f"HTML part {h.part} contains {len(h.tracking_pixels)} tracking pixel(s).",
                           {**part, "sources": h.tracking_pixels[:MAX_EXAMPLES]}))
    if h.remote_resources:
        out.append(Finding("HTML_REMOTE_RESOURCES", Severity.INFO,
                           f"HTML part {h.part} loads {h.remote_resources} remote resource(s) when rendered.",
                           {**part, "count": h.remote_resources}))
    if h.truncated:
        out.append(Finding("HTML_TRUNCATED", Severity.LOW,
                           f"HTML part {h.part} was too large or malformed to analyze fully.", part))
    return out


def _link_text_findings(links: list[Link]) -> list[Finding]:
    """Flag anchors whose visible text shows one domain but whose href goes to another."""
    out, seen = [], set()
    for link in links:
        if link.source != "a":
            continue
        shown = link_text_host(link.text)
        if not shown:
            continue
        _, actual, _ = split_url(link.url)
        if not actual or org_domain(shown) == org_domain(actual):
            continue
        key = (shown, link.url)
        if key in seen:
            continue
        seen.add(key)
        out.append(Finding(
            "URL_TEXT_MISMATCH", Severity.HIGH,
            f"Link text shows '{shown}' but points to '{actual}'.",
            {"text": link.text, "url": link.url, "part": link.part},
        ))
    return out


def _structure_findings(body: BodyAnalysis) -> list[Finding]:
    out = []
    has_text = any(tb.length and tb.preview.strip() for tb in body.text_bodies)
    images = [p for p in body.parts if p.content_type.startswith("image/")]
    if not has_text and images:
        out.append(Finding("BODY_IMAGE_ONLY", Severity.LOW,
                           "Message has images but no readable text (evades text-based filters).",
                           {"images": [p.path for p in images][:MAX_EXAMPLES]}))
    elif not body.text_bodies:
        out.append(Finding("BODY_NO_TEXT", Severity.INFO, "Message has no text/plain or text/html body."))
    return out
