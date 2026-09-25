"""URL extraction from text and per-URL heuristics."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .domains import org_domain
from .models import Finding, Link, Severity, UrlInfo

_TEXT_URL_RE = re.compile(r"(?:\b(?:https?|ftp)://|\bwww\.)[^\s<>\"'`]+", re.I)
_TRAILING_PUNCT = ".,;:!?)]}'\">"

# Link text that is itself a URL or a bare domain, e.g. "https://paypal.com/login" or "paypal.com".
_URLISH_TEXT_RE = re.compile(
    r"^(?:(?:https?|ftp)://)?(?:www\.)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})(?:[:/?#]\S*)?$",
    re.I,
)

URL_SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "lnkd.in",
    "bl.ink", "short.io", "v.gd", "qrco.de", "tinu.be", "shorturl.asia", "u.to", "x.gd",
}
DANGEROUS_SCHEMES = {"javascript", "vbscript", "data", "file"}
IGNORED_SCHEMES = {"mailto", "tel", "sms", "cid", "about"}
MAX_URLS = 5000


def extract_text_urls(text: str, part: str) -> list[Link]:
    links = []
    for m in _TEXT_URL_RE.finditer(text):
        url = m.group(0).rstrip(_TRAILING_PUNCT)
        if len(url) > 4:
            links.append(Link(url=url, source="text", part=part))
    return links


def split_url(url: str) -> tuple[str, str | None, object]:
    """Return (scheme, host, SplitResult-or-None). Never raises."""
    candidate = url.strip()
    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    try:
        parts = urlsplit(candidate)
        host = parts.hostname
    except ValueError:
        scheme = candidate.split(":", 1)[0].lower() if ":" in candidate else ""
        return scheme, None, None
    return parts.scheme.lower(), host, parts


def collect_urls(links: list[Link]) -> list[UrlInfo]:
    """Deduplicate links into UrlInfo records, skipping fragments, relative and mailto links."""
    by_url: dict[str, UrlInfo] = {}
    for link in links:
        scheme, host, _ = split_url(link.url)
        if scheme in IGNORED_SCHEMES or (not scheme and not link.url.startswith("//")):
            continue
        info = by_url.get(link.url)
        if info is None:
            if len(by_url) >= MAX_URLS:
                continue
            info = by_url[link.url] = UrlInfo(
                url=link.url, scheme=scheme, host=host, org_domain=org_domain(host) if host else None,
            )
        source = f"{link.part}:{link.source}"
        if source not in info.sources:
            info.sources.append(source)
        if link.text and link.text not in info.anchor_texts:
            info.anchor_texts.append(link.text)
    return list(by_url.values())


def _ip_host(host: str) -> str | None:
    """Detect IP-literal hosts, including decimal/hex/octal integer forms (http://3232235777/)."""
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        pass
    try:
        if re.fullmatch(r"0x[0-9a-f]+|\d+", host):
            value = int(host, 16) if host.startswith("0x") else int(host)
            if 0 < value <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(value))
    except ValueError:
        pass
    return None


def url_findings(info: UrlInfo) -> list[Finding]:
    out: list[Finding] = []
    ev = {"url": info.url, "sources": info.sources}

    if info.scheme in DANGEROUS_SCHEMES:
        out.append(Finding("URL_DANGEROUS_SCHEME", Severity.HIGH,
                           f"Link uses the '{info.scheme}:' scheme, which can run code or embed content.", ev))
        return out

    _, host, parts = split_url(info.url)
    if parts is None:
        out.append(Finding("URL_MALFORMED", Severity.LOW, "URL could not be parsed.", ev))
        return out

    try:
        has_userinfo = parts.username is not None
        port = parts.port
    except ValueError:
        has_userinfo, port = "@" in parts.netloc, None
    if has_userinfo:
        out.append(Finding("URL_USERINFO", Severity.HIGH,
                           "URL contains user-info before '@'; the real host is after it "
                           f"({host}). Classic trick: http://trusted.com@evil.com/.", ev))
    if "%" in parts.netloc:
        out.append(Finding("URL_ENCODED_HOST", Severity.MEDIUM, "URL host contains percent-encoding.", ev))
    if not host:
        return out

    ip = _ip_host(host)
    if ip:
        out.append(Finding("URL_IP_HOST", Severity.MEDIUM, f"URL points to a raw IP address ({ip}).",
                           {**ev, "ip": ip}))
    if any(label.startswith("xn--") for label in host.split(".")) or not host.isascii():
        out.append(Finding("URL_IDN_HOST", Severity.MEDIUM,
                           f"URL host '{host}' is internationalized (punycode); check for lookalike characters.", ev))
    if host.removeprefix("www.") in URL_SHORTENERS:
        out.append(Finding("URL_SHORTENER", Severity.LOW,
                           f"URL uses shortener '{host}', which hides the real destination.", ev))
    if port not in (None, 80, 443):
        out.append(Finding("URL_NONSTANDARD_PORT", Severity.LOW, f"URL uses port {port}.", ev))
    if not ip and host.count(".") >= 4:
        out.append(Finding("URL_DEEP_SUBDOMAIN", Severity.LOW,
                           f"URL host '{host}' has many subdomain levels (often used to bury a brand name).", ev))
    return out


# Bare anchor text like "invoice.pdf" looks like a domain; ignore common file extensions.
_FILE_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "xlsm", "ppt", "pptx", "zip", "rar", "7z", "txt", "csv",
    "htm", "html", "php", "asp", "aspx", "jpg", "jpeg", "png", "gif", "svg", "exe", "msi", "js",
    "iso", "img", "eml", "msg", "json", "xml", "mp3", "mp4", "wav",
}


def link_text_host(text: str | None) -> str | None:
    """If anchor text looks like a URL or domain, return its host."""
    if not text:
        return None
    text = text.strip()
    m = _URLISH_TEXT_RE.match(text)
    if not m:
        return None
    host = m.group(1).lower()
    explicit = re.match(r"(?:https?|ftp)://|www\.", text, re.I)
    if not explicit and host.rsplit(".", 1)[1] in _FILE_EXTENSIONS:
        return None
    return host
