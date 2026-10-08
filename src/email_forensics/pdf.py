"""Static PDF analysis in the spirit of pdfid / pdf-parser.

Counts risky keywords (JavaScript, auto-actions, Launch, embedded files, forms),
including inside compressed object streams; normalises ``#xx``-escaped names used
to hide keywords; extracts link URIs, launch targets, JavaScript snippets and
embedded files. Nothing is rendered or executed.
"""

from __future__ import annotations

import bisect
import hashlib
import re
import zlib
from dataclasses import dataclass, field

from . import filetype as ft
from .office import EmbeddedObject

MAX_PDF = 50 * 1024 * 1024
MAX_STREAMS = 5000
MAX_INFLATE_TOTAL = 50 * 1024 * 1024
MAX_INFLATE_STREAM = 10 * 1024 * 1024
MAX_RETAIN_STREAM = 2 * 1024 * 1024  # bytes of each stream kept for keyword/JS/embedded analysis
MAX_RETAIN_TOTAL = 64 * 1024 * 1024
MAX_EMBEDDED = 50

KEYWORDS = ("JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "EmbeddedFiles", "URI",
            "SubmitForm", "ImportData", "GoToR", "GoToE", "RichMedia", "XFA", "AcroForm", "JBIG2Decode",
            "ObjStm", "Encrypt", "Page", "Annot")
_KW_RE = re.compile(rb"/(" + b"|".join(k.encode() for k in sorted(KEYWORDS, key=len, reverse=True)) + rb")(?![A-Za-z0-9])")
_NAME_RE = re.compile(rb"/[^\s/<>\[\]()%{}]*#[0-9A-Fa-f]{2}[^\s/<>\[\]()%{}]*")
_HEX_ESC_RE = re.compile(rb"#([0-9A-Fa-f]{2})")
_STREAM_RE = re.compile(rb"stream\r?\n")
_LITERAL = rb"\(((?:\\.|[^\\)]){0,4096})\)"  # literals longer than 4 KB are not URLs/paths worth keeping
MAX_MATCHES = 1000
_URI_RE = re.compile(rb"/URI\s*" + _LITERAL, re.S)
_URI_HEX_RE = re.compile(rb"/URI\s*<([0-9A-Fa-f\s]+)>")
_LAUNCH_ARG_RE = re.compile(rb"/[FP]\s*" + _LITERAL, re.S)
MAX_LAUNCH = 50
_JS_LITERAL_RE = re.compile(rb"/JS\s*" + _LITERAL, re.S)
_OBJ_START_RE = re.compile(rb"\d+\s+\d+\s+obj\b")
_OBJ_END_RE = re.compile(rb"\bendobj\b")
_FILESPEC_NAME_RE = re.compile(rb"/(?:UF|F)\s*" + _LITERAL, re.S)
_JS_MARKERS = re.compile(r"eval\s*\(|unescape\s*\(|String\.fromCharCode|app\.launchURL|this\.exportDataObject|"
                         r"util\.printf|getAnnots|spell\.customDictionaryOpen|Collab\.getIcon|submitForm|"
                         r"app\.openDoc|xfa\.host|ActiveXObject", re.I)


@dataclass
class PdfAnalysis:
    version: str | None = None
    keywords: dict[str, int] = field(default_factory=dict)
    obfuscated_names: list[str] = field(default_factory=list)
    uris: list[str] = field(default_factory=list)
    launch: list[str] = field(default_factory=list)
    javascript: list[str] = field(default_factory=list)  # snippets
    javascript_markers: list[str] = field(default_factory=list)
    embedded: list[EmbeddedObject] = field(default_factory=list)
    embedded_names: list[str] = field(default_factory=list)
    incremental_updates: int = 0
    streams: int = 0
    inflated_bytes: int = 0
    truncated: bool = False


def _unescape_literal(raw: bytes) -> str:
    out, i = bytearray(), 0
    while i < len(raw):
        c = raw[i]
        if c == 0x5C and i + 1 < len(raw):  # backslash
            n = raw[i + 1]
            simple = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}
            if n in simple:
                out.append(simple[n])
                i += 2
            elif 0x30 <= n <= 0x37:
                m = re.match(rb"[0-7]{1,3}", raw[i + 1:i + 4])
                out.append(int(m.group(0), 8) & 0xFF)
                i += 1 + len(m.group(0))
            elif n in (0x0A, 0x0D):
                i += 2
            else:
                out.append(n)
                i += 2
        else:
            out.append(c)
            i += 1
    data = bytes(out)
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", "replace")
    return data.decode("latin-1")


def _normalise(data: bytes) -> bytes:
    return _HEX_ESC_RE.sub(lambda m: bytes([int(m.group(1), 16)]), data)


def _streams(data: bytes, res: PdfAnalysis) -> list[tuple[bytes, bytes]]:
    """Return [(dictionary text, decoded data)] for each stream, inflating FlateDecode within budget."""
    out = []
    budget = MAX_INFLATE_TOTAL
    retained = 0
    ends = [m.start() for m in re.finditer(rb"endstream", data)]
    for m in _STREAM_RE.finditer(data):
        if len(out) >= MAX_STREAMS or retained >= MAX_RETAIN_TOTAL:
            res.truncated = True
            break
        start = m.end()
        dict_start = data.rfind(b"obj", max(0, m.start() - 4000), m.start())
        dictionary = _normalise(data[dict_start if dict_start >= 0 else max(0, m.start() - 1000):m.start()])
        i = bisect.bisect_left(ends, start)  # sorted positions: no rescanning per stream
        end = ends[i] if i < len(ends) else min(len(data), start + MAX_INFLATE_STREAM)
        raw = data[start:end]
        decoded = raw
        if b"/FlateDecode" in dictionary or b"/Fl " in dictionary or b"/Fl/" in dictionary or b"/Fl]" in dictionary:
            if budget <= 0:
                res.truncated = True
            else:
                d = zlib.decompressobj()
                try:
                    decoded = d.decompress(raw, min(MAX_INFLATE_STREAM, budget))
                except zlib.error:
                    decoded = b""
                budget -= len(decoded)
                res.inflated_bytes += len(decoded)
        if b"/EmbeddedFile" not in dictionary:  # embedded files are hashed whole; others only scanned
            decoded = decoded[:MAX_RETAIN_STREAM]
        retained += len(decoded)
        out.append((dictionary, decoded))
    res.streams = len(out)
    return out


def _findall(regex: re.Pattern, blob: bytes, limit: int = MAX_MATCHES) -> list:
    out = []
    for m in regex.finditer(blob):
        out.append(m.group(1))
        if len(out) >= limit:
            break
    return out


def _object_bodies(data: bytes, limit: int = 100_000):
    """Yield 'N G obj ... endobj' bodies, pairing starts and ends in one sorted pass."""
    ends = [m.start() for m in _OBJ_END_RE.finditer(data)]
    for m in _OBJ_START_RE.finditer(data):
        i = bisect.bisect_left(ends, m.end())
        if i < len(ends) and ends[i] - m.end() <= limit:
            yield data[m.end():ends[i]]


def analyze_pdf(data: bytes) -> PdfAnalysis:
    res = PdfAnalysis()
    if len(data) > MAX_PDF:
        data = data[:MAX_PDF]
        res.truncated = True
    m = re.search(rb"%PDF-(\d\.\d)", data[:1024])
    res.version = m.group(1).decode() if m else None
    res.incremental_updates = max(0, data.count(b"%%EOF") - 1)

    res.obfuscated_names = sorted({n.decode("latin-1") for n in _NAME_RE.findall(data)
                                   if _KW_RE.fullmatch(_normalise(n))})[:20]
    streams = _streams(data, res)
    # Keywords inside compressed object streams count too: that is where they hide.
    corpus = [_normalise(data)] + [_normalise(d) for dictionary, d in streams if b"/ObjStm" in dictionary]
    counts: dict[str, int] = {}
    for blob in corpus:
        for km in _KW_RE.finditer(blob):
            k = km.group(1).decode()
            counts[k] = counts.get(k, 0) + 1
    res.keywords = dict(sorted(counts.items()))

    uris: list[str] = []
    for blob in corpus:
        uris += [_unescape_literal(u) for u in _findall(_URI_RE, blob)]
        for h in _findall(_URI_HEX_RE, blob):
            try:
                uris.append(bytes.fromhex(re.sub(rb"\s+", b"", h[:8192]).decode()).decode("latin-1"))
            except ValueError:
                pass
        for i, lm in enumerate(re.finditer(rb"/Launch", blob)):
            if i >= MAX_LAUNCH:
                break
            window = blob[lm.end():lm.end() + 600]  # the action's /F (file) and /P (parameters)
            res.launch += [_unescape_literal(x) for x in _findall(_LAUNCH_ARG_RE, window, 4)]
        res.javascript += [_unescape_literal(js)[:500] for js in _findall(_JS_LITERAL_RE, blob, 50)]
    res.uris = list(dict.fromkeys(u.strip() for u in uris if u.strip()))[:500]
    res.launch = list(dict.fromkeys(res.launch))[:20]

    for dictionary, decoded in streams:
        if b"/JS" in dictionary or b"/JavaScript" in dictionary:
            res.javascript.append(decoded[:500].decode("latin-1", "replace"))
        elif counts.get("JS") or counts.get("JavaScript"):
            text = decoded[:200_000].decode("latin-1", "replace")
            if _JS_MARKERS.search(text):
                res.javascript.append(text[:500])
        if b"/EmbeddedFile" in dictionary and len(res.embedded) < MAX_EMBEDDED:
            t = ft.detect(decoded)
            res.embedded.append(EmbeddedObject("pdf:/EmbeddedFile", None, len(decoded),
                                               hashlib.sha256(decoded).hexdigest(), t.id if t else None))
    res.javascript = [j for j in dict.fromkeys(res.javascript) if j.strip()][:20]
    res.javascript_markers = sorted({m.group(0).strip() for j in res.javascript for m in _JS_MARKERS.finditer(j)})
    if counts.get("EmbeddedFile") or counts.get("EmbeddedFiles"):
        names = []
        for body in _object_bodies(_normalise(data)):
            if b"/Filespec" in body or b"/EF" in body:
                names += [_unescape_literal(n) for n in _FILESPEC_NAME_RE.findall(body)]
        res.embedded_names = [n for n in dict.fromkeys(names) if "." in n][:20]
    return res
