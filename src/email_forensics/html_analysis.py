"""Static HTML body analysis.

Static only: the HTML is parsed, never rendered, and no remote resource is fetched.
We collect what the reader sees (visible text, link text) separately from what is
hidden from them (CSS-hidden text, scripts, forms, tracking pixels).
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

from .models import HtmlAnalysis, HtmlForm, Link
from .urls import extract_text_urls

MAX_HTML_CHARS = 5_000_000
MAX_SNIPPETS = 50
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
            hidden = self._hidden or "hidden" in a or is_hidden_style(style)
            self.stack.append((tag, hidden, self._not_rendered or tag in _NOT_RENDERED))

    def handle_endtag(self, tag):
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
