"""Body analysis: MIME structure, text/HTML bodies, URLs, and the findings they produce."""

from __future__ import annotations

import re
from email.message import Message

from .domains import org_domain
from .html_analysis import analyze_html, html_findings
from .mime import MimeTree, decode_text, walk_mime
from .models import BodyAnalysis, Finding, Link, Severity, TextBody
from .textcheck import invisible_char_findings
from .urls import collect_urls, extract_text_urls, link_text_host, split_url, url_findings

TEXT_PREVIEW_CHARS = 4000
MAX_EXAMPLES = 10


def analyze_body(msg: Message, tree: MimeTree | None = None) -> tuple[BodyAnalysis, list[Finding]]:
    tree = tree or walk_mime(msg)
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
            findings += html_findings(html)
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
    findings += _alternative_findings(body)
    return body, findings


def _words(text: str) -> set[str]:
    return set(re.findall(r"[^\W\d_]{3,}", text.lower()))


def _alternative_findings(body: BodyAnalysis) -> list[Finding]:
    """text/plain and text/html alternatives that say different things: filters often read one
    version, people see the other."""
    types = {p.path: p.content_type for p in body.parts}
    groups: dict[str, dict[str, TextBody]] = {}
    for tb in body.text_bodies:
        parent = tb.part.rsplit(".", 1)[0] if "." in tb.part else ""
        if types.get(parent) == "multipart/alternative":
            groups.setdefault(parent, {})[tb.content_type] = tb
    out = []
    for parent, versions in groups.items():
        plain, html = versions.get("text/plain"), versions.get("text/html")
        if not plain or not html:
            continue
        a, b = _words(plain.preview), _words(html.preview)
        if len(a) < 15 or len(b) < 15:
            continue
        similarity = len(a & b) / len(a | b)
        if similarity < 0.2:
            out.append(Finding("BODY_ALTERNATIVES_DIFFER", Severity.MEDIUM,
                               f"The plain-text and HTML versions in part {parent} share only {similarity:.0%} of their "
                               "words; filters and people may be reading different messages.",
                               {"part": parent, "similarity": round(similarity, 3),
                                "plain_words": len(a), "html_words": len(b)}))
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
