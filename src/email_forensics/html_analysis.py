"""Static HTML body analysis.

Static only: the HTML is parsed, never rendered, and no remote resource is fetched.
We collect what the reader sees (visible text, link text) separately from what is
hidden from them (CSS-hidden text, scripts, forms, tracking pixels).
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

from .models import Finding, HtmlAnalysis, HtmlForm, Link, Severity
from .urls import extract_text_urls

MAX_HTML_CHARS = 5_000_000
MAX_SNIPPETS = 50
MAX_EXAMPLES = 10
SNIPPET_CHARS = 200
VISIBLE_TEXT_CHARS = 4000

_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
         "param", "source", "track", "wbr", "frame"}
_NOT_RENDERED = {"script", "style", "head", "title", "template", "xml"}
_BLOCK = {"p", "div", "br", "tr", "li", "table", "h1", "h2", "h3", "h4", "h5", "h6",
          "blockquote", "section", "article", "header", "footer", "ul", "ol", "hr"}

_HIDDEN_STYLE_RES = [
    re.compile(r"display\s*:\s*none"),
    re.compile(r"visibility\s*:\s*hidden"),
    re.compile(r"(?<![-\w])font-size\s*:\s*(?:0+(?:\.0*)?|\.0+)(?:px|pt|em|rem|%)?\s*(?:;|$|!)"),
    re.compile(r"(?<![-\w])font-size\s*:\s*(?:0?\.\d+|1)px"),
    re.compile(r"(?<![-\w])opacity\s*:\s*(?:0+(?:\.0*)?|\.0+)\s*(?:;|$|!)"),
    re.compile(r"(?<![-\w])(?:max-)?height\s*:\s*0(?:px)?\s*(?:;|$|!)[^\"]*overflow\s*:\s*hidden"),
]
_COLOR_RE = re.compile(r"(?<![-\w])color\s*:\s*([^;!]+)")
_BG_RE = re.compile(r"background(?:-color)?\s*:\s*([^;!]+)")
_CSS_URL_RE = re.compile(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", re.I)
_META_REFRESH_RE = re.compile(r"url\s*=\s*['\"]?([^'\"]+)", re.I)
_WS_RE = re.compile(r"[ \t\r\f\v]+")


def is_hidden_style(style: str) -> bool:
    style = style.lower()
    if any(r.search(style) for r in _HIDDEN_STYLE_RES):
        return True
    color, bg = _COLOR_RE.search(style), _BG_RE.search(style)
    return bool(color and bg and color.group(1).strip() == bg.group(1).strip())


_CSS_RULE_RE = re.compile(r"([^{}]+)\{([^{}]*)\}")
_SIMPLE_SELECTOR_RE = re.compile(r"^[a-z0-9]*([.#])([\w-]+)$", re.I)


def hidden_selectors(css: str) -> tuple[set[str], set[str]]:
    """Classes and ids that a <style> block hides (simple .cls / #id selectors).

    Rules inside @media blocks are ignored: responsive emails routinely hide
    desktop-only content on phones, which is not evasion.
    """
    css = re.sub(r"/\*.*?\*/", "", css[:500_000], flags=re.S)
    css = _strip_at_blocks(css)
    classes, ids = set(), set()
    for selectors, decls in _CSS_RULE_RE.findall(css):
        if not is_hidden_style(decls):
            continue
        for sel in selectors.split(","):
            m = _SIMPLE_SELECTOR_RE.match(sel.strip())
            if m:
                (classes if m.group(1) == "." else ids).add(m.group(2).lower())
    return classes, ids


def _strip_at_blocks(css: str) -> str:
    out, i = [], 0
    while True:
        j = css.find("@", i)
        if j < 0:
            out.append(css[i:])
            return "".join(out)
        out.append(css[i:j])
        brace = css.find("{", j)
        semi = css.find(";", j)
        if brace < 0 or (0 <= semi < brace):  # @import ...; style statements
            i = semi + 1 if semi >= 0 else len(css)
            continue
        depth, k = 0, brace
        while k < len(css):
            if css[k] == "{":
                depth += 1
            elif css[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        i = k + 1


def is_remote(url: str) -> bool:
    return url.lower().lstrip().startswith(("http://", "https://", "//"))


def _dimension(value: str | None) -> int | None:
    if not value:
        return None
    m = re.match(r"\s*(\d+)", value)
    return int(m.group(1)) if m else None


class _Parser(HTMLParser):
    def __init__(self, part: str) -> None:
        super().__init__(convert_charrefs=True)
        self.result = HtmlAnalysis(part=part)
        self.part = part
        # Each entry: (tag, hidden, not_rendered), with flags inherited from parents.
        self.stack: list[tuple[str, bool, bool]] = []
        self.visible: list[str] = []
        self.hidden: list[str] = []
        self.anchor: Link | None = None
        self.anchor_text: list[str] = []
        self.form: HtmlForm | None = None
        self.script_text: list[str] = []
        self.style_text: list[str] = []
        self.hidden_classes: set[str] = set()
        self.hidden_ids: set[str] = set()

    # -- state helpers -------------------------------------------------------
    @property
    def _hidden(self) -> bool:
        return bool(self.stack) and self.stack[-1][1]

    @property
    def _not_rendered(self) -> bool:
        return bool(self.stack) and self.stack[-1][2]

    def _link(self, url: str | None, source: str) -> None:
        if url and url.strip():
            self.result.links.append(Link(url=url.strip(), source=source, part=self.part))
            if is_remote(url) and source not in ("a", "form"):
                self.result.remote_resources += 1

    # -- HTMLParser callbacks ------------------------------------------------
    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        style = a.get("style", "")

        for name in a:
            if name.startswith("on"):
                self.result.event_handlers.append(f"{tag}.{name}")
        for url in _CSS_URL_RE.findall(style):
            self._link(url, "css")

        if tag in ("a", "area") and "href" in a:
            self._close_anchor()
            self.anchor = Link(url=a["href"].strip(), source="a", part=self.part)
            self.anchor_text = []
        elif tag == "img" or (tag == "input" and a.get("type", "").lower() == "image"):
            src = a.get("src")
            self._link(src, "img")
            w = _dimension(a.get("width")) or _dimension(_style_value(style, "width"))
            h = _dimension(a.get("height")) or _dimension(_style_value(style, "height"))
            if src and is_remote(src) and w is not None and h is not None and w <= 1 and h <= 1:
                self.result.tracking_pixels.append(src)
        elif tag in ("iframe", "frame", "embed", "object"):
            src = a.get("src") or a.get("data")
            self.result.embedded_frames.append(src or f"<{tag}>")
            self._link(src, "iframe")
        elif tag == "script":
            self.result.scripts += 1
            self._link(a.get("src"), "script")
        elif tag == "link":
            self._link(a.get("href"), "link")
        elif tag == "form":
            self.form = HtmlForm(action=a.get("action") or None, method=(a.get("method") or None))
            self.result.forms.append(self.form)
            self._link(a.get("action"), "form")
        elif tag in ("input", "button", "select", "textarea"):
            if self.form is None:
                self.form = HtmlForm(action=None, method=None)
                self.result.forms.append(self.form)
            self.form.input_types.append((a.get("type") or ("text" if tag == "input" else tag)).lower())
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = _META_REFRESH_RE.search(a.get("content", ""))
            if m:
                self.result.meta_refresh = m.group(1).strip()
                self._link(self.result.meta_refresh, "meta-refresh")
        elif tag == "base" and a.get("href"):
            self.result.base_href = a["href"]
            self._link(a["href"], "base")
        if "background" in a and tag != "base":
            self._link(a["background"], "img")

        if tag in _BLOCK:
            self.visible.append("\n")
        if tag not in _VOID:
            classes = set(a.get("class", "").lower().split())
            hidden = (self._hidden or "hidden" in a or is_hidden_style(style)
                      or bool(classes & self.hidden_classes) or a.get("id", "").lower() in self.hidden_ids)
            self.stack.append((tag, hidden, self._not_rendered or tag in _NOT_RENDERED))

    def handle_endtag(self, tag):
        if tag == "style" and self.style_text:
            classes, ids = hidden_selectors("".join(self.style_text))
            self.hidden_classes |= classes
            self.hidden_ids |= ids
            self.style_text = []
        if tag in ("a", "area"):
            self._close_anchor()
        elif tag == "form":
            self.form = None
        if tag in _BLOCK:
            self.visible.append("\n")
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if self.stack and self.stack[-1][0] == "script":
            self.script_text.append(data)
        elif self.stack and self.stack[-1][0] == "style":
            self.style_text.append(data)
        if self._not_rendered:
            return
        if self._hidden:
            if data.strip():
                self.hidden.append(data.strip())
            return
        self.visible.append(data)
        if self.anchor is not None:
            self.anchor_text.append(data)

    def _close_anchor(self):
        if self.anchor is not None:
            text = _WS_RE.sub(" ", "".join(self.anchor_text)).strip()
            self.anchor.text = text or None
            self.result.links.append(self.anchor)
            self.anchor = None

    def finish(self) -> HtmlAnalysis:
        self.close()
        self._close_anchor()
        for link in extract_text_urls("\n".join(self.script_text), self.part):
            link.source = "script"
            self.result.links.append(link)
        text = _WS_RE.sub(" ", "".join(self.visible))
        self.full_text = re.sub(r"\s*\n\s*", "\n", text).strip()
        self.result.visible_text = self.full_text[:VISIBLE_TEXT_CHARS]
        self.result.hidden_text = [h[:SNIPPET_CHARS] for h in self.hidden[:MAX_SNIPPETS]]
        return self.result


def _style_value(style: str, prop: str) -> str | None:
    m = re.search(rf"(?<![-\w]){prop}\s*:\s*([^;]+)", style, re.I)
    return m.group(1) if m else None


def analyze_html(html: str, part: str) -> tuple[HtmlAnalysis, str]:
    """Return the analysis and the full (untruncated) visible text."""
    parser = _Parser(part)
    truncated = len(html) > MAX_HTML_CHARS
    try:
        parser.feed(html[:MAX_HTML_CHARS])
    except Exception:
        # HTMLParser is lenient, but never let a parser bug abort the whole analysis.
        truncated = True
    result = parser.finish()
    result.truncated = truncated
    return result, parser.full_text


def html_findings(h: HtmlAnalysis) -> list[Finding]:
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
