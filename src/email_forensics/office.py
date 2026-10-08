"""Static analysis of Office documents: OLE (legacy), OOXML and RTF.

Extracts VBA macros, Excel 4.0 (XLM) macro sheets, DDE fields, embedded OLE
packages (Ole10Native), ActiveX controls, external relationships and document
metadata. Documents are never opened in Office.
"""

from __future__ import annotations

import binascii
import hashlib
import io
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import filetype as ft
from .cfb import CompoundFile, open_cfb
from .vba import VbaModule, extract_vba

MAX_XML = 5_000_000
MAX_EMBEDDED = 50
MAX_MEMBER = 50 * 1024 * 1024
_ZIP_ERRORS = (KeyError, zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError, zlib.error,
               NotImplementedError)


@dataclass
class EmbeddedObject:
    source: str  # where it was found, e.g. "word/embeddings/oleObject1.bin:Ole10Native"
    name: str | None
    size: int
    sha256: str
    detected_type: str | None = None


@dataclass
class OfficeAnalysis:
    metadata: dict[str, str] = field(default_factory=dict)
    vba: list[VbaModule] = field(default_factory=list)
    xlm_macros: list[str] = field(default_factory=list)  # suspicious XLM formulas
    xlm_autoexec: bool = False
    dde: list[str] = field(default_factory=list)
    activex: list[str] = field(default_factory=list)
    embedded: list[EmbeddedObject] = field(default_factory=list)
    external: list[dict] = field(default_factory=list)  # [{"type", "target"}]
    rtf_object_classes: list[str] = field(default_factory=list)


def _embedded(source: str, name: str | None, data: bytes) -> EmbeddedObject:
    t = ft.detect(data)
    return EmbeddedObject(source, name, len(data), hashlib.sha256(data).hexdigest(), t.id if t else None)


# --------------------------------------------------------------------------- OLE


def parse_ole10native(data: bytes) -> tuple[str | None, bytes] | None:
    """Return (filename, payload) from an Ole10Native stream (the 'Package' object)."""
    try:
        pos = 4 + 2
        def cstr(p: int) -> tuple[str, int]:
            end = data.index(b"\x00", p)
            return data[p:end].decode("latin-1"), end + 1
        label, pos = cstr(pos)
        _, pos = cstr(pos)  # source path
        pos += 8
        _, pos = cstr(pos)  # temp path
        size = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if size > len(data) - pos:
            size = len(data) - pos
        return label or None, data[pos:pos + size]
    except (ValueError, struct.error):
        return None


_SUMMARY_PIDS = {2: "title", 3: "subject", 4: "author", 5: "keywords", 6: "comments", 7: "template",
                 8: "last_saved_by", 9: "revision", 11: "last_printed", 12: "created", 13: "last_saved",
                 18: "application"}
_DOCSUMMARY_PIDS = {14: "manager", 15: "company"}


def parse_property_set(data: bytes, pids: dict[int, str]) -> dict[str, str]:
    """Parse the first section of an OLE property set stream (MS-OLEPS)."""
    out: dict[str, str] = {}
    try:
        if struct.unpack_from("<H", data, 0)[0] != 0xFFFE:
            return out
        offset = struct.unpack_from("<I", data, 28 + 16)[0]
        _, count = struct.unpack_from("<II", data, offset)
        codepage = "cp1252"
        props = [struct.unpack_from("<II", data, offset + 8 + i * 8) for i in range(min(count, 200))]
        for pid, poff in props:
            if pid == 1:
                cp = struct.unpack_from("<H", data, offset + poff + 4)[0]
                codepage = {65001: "utf-8", 1200: "utf-16-le"}.get(cp, f"cp{cp}")
        for pid, poff in props:
            name = pids.get(pid)
            if not name:
                continue
            base = offset + poff
            vtype = struct.unpack_from("<I", data, base)[0] & 0xFFFF
            if vtype == 0x1E:  # VT_LPSTR
                n = struct.unpack_from("<I", data, base + 4)[0]
                raw = data[base + 8:base + 8 + min(n, 4096)]
                try:
                    value = raw.decode(codepage, "replace")
                except LookupError:
                    value = raw.decode("cp1252", "replace")
                value = value.rstrip("\x00").strip()
            elif vtype == 0x1F:  # VT_LPWSTR
                n = struct.unpack_from("<I", data, base + 4)[0]
                value = data[base + 8:base + 8 + min(n, 2048) * 2].decode("utf-16-le", "replace").rstrip("\x00")
            elif vtype == 0x40:  # VT_FILETIME
                ticks = struct.unpack_from("<Q", data, base + 4)[0]
                if not ticks:
                    continue
                value = (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)).isoformat()
            elif vtype in (2, 3):
                value = str(struct.unpack_from("<i" if vtype == 3 else "<h", data, base + 4)[0])
            else:
                continue
            if value:
                out[name] = value
    except (struct.error, OverflowError, ValueError):
        pass
    return out


def analyze_ole(data: bytes, cf: CompoundFile | None = None) -> OfficeAnalysis:
    res = OfficeAnalysis()
    cf = cf or open_cfb(data)
    if cf is None:
        return res
    for stream, pids in (("\x05SummaryInformation", _SUMMARY_PIDS), ("\x05DocumentSummaryInformation", _DOCSUMMARY_PIDS)):
        raw = _safe_read(cf, stream)
        if raw:
            res.metadata.update(parse_property_set(raw, pids))
    res.vba = extract_vba(cf)
    for entry in cf.streams():
        if entry.path[-1].lower() == "\x01ole10native" and len(res.embedded) < MAX_EMBEDDED:
            parsed = parse_ole10native(_safe_read_entry(cf, entry) or b"")
            if parsed:
                res.embedded.append(_embedded("/".join(entry.path), parsed[0], parsed[1]))
    return res


def _safe_read(cf: CompoundFile, *path: str) -> bytes | None:
    try:
        return cf.read_path(*path)
    except ValueError:
        return None


def _safe_read_entry(cf: CompoundFile, entry) -> bytes | None:
    try:
        return cf.read(entry)
    except ValueError:
        return None


# --------------------------------------------------------------------------- OOXML

_DDE_RE = re.compile(r"\bDDE(?:AUTO)?\b[^<]{0,300}", re.I)
_INSTR_RE = re.compile(r"<w:instrText[^>]*>([^<]*)</w:instrText>|w:instr=\"([^\"]*)\"", re.I)
_REL_RE = re.compile(r"<Relationship\b([^>]*)/?>", re.I)
_ATTR_RE = re.compile(r'(\w+)="([^"]*)"')
_XLM_SUSPICIOUS = re.compile(r"\b(EXEC|CALL|REGISTER|RUN|FORMULA(?:\.FILL)?|URLDownloadToFile\w*|CreateThread|"
                             r"VirtualAlloc|WriteProcessMemory|FOPEN|FWRITE|SET\.NAME|GET\.WORKSPACE|"
                             r"GET\.WINDOW|ALERT|HALT|CHAR)\s*\(", re.I)
_CORE_FIELDS = {"dc:creator": "author", "cp:lastModifiedBy": "last_saved_by", "dcterms:created": "created",
                "dcterms:modified": "last_saved", "dc:title": "title", "cp:revision": "revision",
                "Application": "application", "Company": "company", "AppVersion": "app_version",
                "TotalTime": "editing_minutes", "Manager": "manager", "Template": "template"}


def _read_member(zf: zipfile.ZipFile, name: str, limit: int = MAX_MEMBER) -> bytes:
    """Read a zip member, refusing ones whose declared size exceeds `limit` (zip bombs)."""
    if zf.getinfo(name).file_size > limit:
        raise ValueError(f"{name} is larger than {limit} bytes")
    with zf.open(name) as fh:
        return fh.read(limit + 1)[:limit]


def _xml_text(zf: zipfile.ZipFile, name: str) -> str:
    return _read_member(zf, name, MAX_XML).decode("utf-8", "replace")


def analyze_ooxml(data: bytes) -> OfficeAnalysis:
    res = OfficeAnalysis()
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except _ZIP_ERRORS:
        return res
    with zf:
        names = zf.namelist()[:10_000]
        lower = {n.lower(): n for n in names}
        for meta in ("docProps/core.xml", "docProps/app.xml"):
            if meta.lower() in lower:
                text = _safe_xml(zf, lower[meta.lower()])
                for tag, key in _CORE_FIELDS.items():
                    m = re.search(rf"<{re.escape(tag)}\b[^>]*>([^<]{{1,500}})</{re.escape(tag)}>", text)
                    if m:
                        res.metadata[key] = m.group(1).strip()

        for name in names:
            low = name.lower()
            try:
                if low.endswith("vbaproject.bin"):
                    cf = open_cfb(_read_member(zf, name))
                    if cf:
                        res.vba += extract_vba(cf)
                elif "/macrosheets/" in low and low.endswith(".xml"):
                    text = _safe_xml(zf, name)
                    formulas = re.findall(r"<f>([^<]{1,500})</f>", text)
                    hits = [f for f in formulas if _XLM_SUSPICIOUS.search(f)]
                    res.xlm_macros += (hits or formulas[:1] or [f"(macro sheet {name})"])[:20]
                elif low.endswith("workbook.xml"):
                    if re.search(r"_xlnm\.Auto_(?:Open|Activate)|>Auto_Open<", _safe_xml(zf, name), re.I):
                        res.xlm_autoexec = True
                elif "/activex/" in low and low.endswith((".xml", ".bin")):
                    res.activex.append(name)
                elif low.startswith(("word/", "xl/externallinks")) and low.endswith(".xml"):
                    text = _safe_xml(zf, name)
                    for m in _INSTR_RE.finditer(text):
                        instr = (m.group(1) or m.group(2) or "").strip()
                        if _DDE_RE.search(instr):
                            res.dde.append(instr[:300])
                    if "ddelink" in text.lower():
                        res.dde.append(f"ddeLink in {name}")
                elif "/embeddings/" in low and len(res.embedded) < MAX_EMBEDDED:
                    payload = _read_member(zf, name)
                    cf = open_cfb(payload)
                    native = None
                    if cf:
                        for entry in cf.streams():
                            if entry.path[-1].lower() == "\x01ole10native":
                                native = parse_ole10native(_safe_read_entry(cf, entry) or b"")
                                break
                    if native:
                        res.embedded.append(_embedded(f"{name}:Ole10Native", native[0], native[1]))
                    else:
                        res.embedded.append(_embedded(name, name.rsplit("/", 1)[-1], payload))
                if low.endswith(".rels"):
                    for m in _REL_RE.finditer(_safe_xml(zf, name)):
                        attrs = dict(_ATTR_RE.findall(m.group(1)))
                        if attrs.get("TargetMode", "").lower() == "external":
                            res.external.append({"type": attrs.get("Type", "").rsplit("/", 1)[-1],
                                                 "target": attrs.get("Target", ""), "part": name})
            except _ZIP_ERRORS:
                continue
    res.dde = res.dde[:20]
    res.external = res.external[:200]
    return res


def _safe_xml(zf: zipfile.ZipFile, name: str) -> str:
    try:
        return _xml_text(zf, name)
    except _ZIP_ERRORS:
        return ""


# --------------------------------------------------------------------------- RTF

_OBJCLASS_RE = re.compile(rb"\\objclass\s+([^}\\]{1,100})", re.I)
_OBJDATA_RE = re.compile(rb"\\objdata\b\s*([0-9a-fA-F\s]{16,})", re.I)
# Object classes abused by well-known RTF exploits.
RTF_EXPLOIT_CLASSES = {
    "equation.3": "Equation Editor (CVE-2017-11882 / CVE-2018-0802)",
    "equation.2": "Equation Editor",
    "ole2link": "OLE2Link (CVE-2017-0199 remote HTA)",
    "htmlfile": "htmlfile (CVE-2017-0199)",
    "word.document.8": "embedded Word document",
    "package": "Package (embedded file)",
    "forms.htmlfile.1": "Forms.HTML (CVE-2017-0199 variants)",
    "msxml2.saxxmlreader": "MSXML (exploit carrier)",
}


def analyze_rtf(data: bytes) -> OfficeAnalysis:
    res = OfficeAnalysis()
    head = data[:20_000_000]
    res.rtf_object_classes = sorted({m.group(1).strip().decode("latin-1") for m in _OBJCLASS_RE.finditer(head)})[:20]
    for i, m in enumerate(_OBJDATA_RE.finditer(head)):
        if i >= MAX_EMBEDDED:
            break
        hexdata = re.sub(rb"\s+", b"", m.group(1))[:20_000_000]
        try:
            blob = binascii.unhexlify(hexdata[: len(hexdata) // 2 * 2])
        except binascii.Error:
            continue
        pos = blob.find(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
        if pos >= 0:
            sub = analyze_ole(blob[pos:])
            res.embedded += sub.embedded
            res.vba += sub.vba
            if not sub.embedded:
                res.embedded.append(_embedded(f"objdata#{i}", None, blob[pos:]))
        else:
            # OLE1 "Package" objects carry an Ole10Native-like payload after the class name.
            pkg = blob.find(b"Package\x00")
            if pkg >= 0:
                # OLE1: ClassName "Package\0", empty TopicName/ItemName (4-byte lengths), then the
                # native data, which has the Ole10Native layout (size-prefixed).
                parsed = parse_ole10native(blob[pkg + 8 + 8:])
                if parsed:
                    res.embedded.append(_embedded(f"objdata#{i}:Package", parsed[0], parsed[1]))
                    continue
            res.embedded.append(_embedded(f"objdata#{i}", None, blob))
    return res
