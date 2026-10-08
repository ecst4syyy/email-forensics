"""Deep static analysis of attachment payloads, dispatched by detected file type.

Office (OLE/OOXML/RTF), PDF, Windows shortcuts, OneNote and script files each get
a format-specific analyzer; this module turns their results into findings and
feeds extracted URLs back into the attachment's URL list.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field

from . import filetype as ft
from .lnk import LnkInfo, parse_lnk
from .mime import decode_text
from .models import Attachment, Finding, Link, Severity
from .office import EmbeddedObject, OfficeAnalysis, analyze_ole, analyze_ooxml, analyze_rtf, RTF_EXPLOIT_CLASSES
from .pdf import PdfAnalysis, analyze_pdf
from .scripts import SCRIPT_EXTENSIONS, ScriptAnalysis, analyze_script
from .urls import collect_urls, url_findings

MAX_EXAMPLES = 10
_LOLBINS = re.compile(r"powershell|pwsh|cmd(?:\.exe)?|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|"
                      r"msiexec|curl|forfiles|conhost|explorer\.exe\s+\S+\.(?:js|vbs|hta)", re.I)
_DOC_ICONS = re.compile(r"\.(?:pdf|docx?|xlsx?|pptx?|txt|jpe?g|png)\b|imageres\.dll|shell32\.dll|moricons\.dll", re.I)
ONENOTE_FILE_GUID = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")


@dataclass
class PayloadAnalysis:
    kind: str
    office: OfficeAnalysis | None = None
    pdf: PdfAnalysis | None = None
    lnk: LnkInfo | None = None
    script: ScriptAnalysis | None = None
    embedded: list[EmbeddedObject] = field(default_factory=list)  # OneNote embedded files


def analyze_payload(att: Attachment, data: bytes, label: str) -> tuple[PayloadAnalysis | None, list[Finding]]:
    t = att.detected_type
    ext = att.extension or ""
    ev = {"part": att.part, "filename": att.filename, "sha256": att.sha256}
    if t == ft.OLE.id:
        pa = PayloadAnalysis("ole", office=analyze_ole(data))
    elif t in (ft.OOXML_WORD.id, ft.OOXML_EXCEL.id, ft.OOXML_PPT.id):
        pa = PayloadAnalysis("ooxml", office=analyze_ooxml(data))
    elif t == ft.RTF.id:
        pa = PayloadAnalysis("rtf", office=analyze_rtf(data))
    elif t == ft.PDF.id:
        pa = PayloadAnalysis("pdf", pdf=analyze_pdf(data))
    elif t == ft.LNK.id:
        pa = PayloadAnalysis("lnk", lnk=parse_lnk(data))
    elif t == ft.ONENOTE.id:
        pa = PayloadAnalysis("onenote", embedded=extract_onenote(data))
    elif ext in SCRIPT_EXTENSIONS or t == ft.SHEBANG.id:
        text, _ = decode_text(data, "utf-8")
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            text, _ = decode_text(data, "utf-16")
        pa = PayloadAnalysis("script", script=analyze_script(text))
    else:
        return None, []

    findings: list[Finding] = []
    if pa.office:
        findings += _office_findings(pa.office, label, ev)
        _add_urls(att, [e["target"] for e in pa.office.external if e["type"] == "hyperlink"], "office-link")
        _add_urls(att, [i for m in pa.office.vba for i in m.iocs if "://" in i], "vba")
    if pa.pdf:
        findings += _pdf_findings(pa.pdf, label, ev)
        _add_urls(att, pa.pdf.uris, "pdf-uri")
    if pa.lnk:
        findings += _lnk_findings(pa.lnk, label, ev)
        if pa.lnk.arguments:
            sa = analyze_script(pa.lnk.arguments)
            findings += _script_findings(sa, f"{label} (shortcut arguments)", ev)
            _add_urls(att, sa.urls, "lnk-args")
    if pa.script:
        findings += _script_findings(pa.script, label, ev)
        _add_urls(att, pa.script.urls, "script")
    if pa.kind == "onenote":
        findings += _embedded_findings(pa.embedded, label, ev, "ONENOTE_EMBEDDED_FILE")
    for url in att.urls:
        if any(s.endswith((":pdf-uri", ":office-link", ":vba", ":script", ":lnk-args")) for s in url.sources):
            findings += url_findings(url)
    return pa, findings


def _add_urls(att: Attachment, urls: list[str], source: str) -> None:
    links = [Link(url=u, source=source, part=att.part) for u in urls if u]
    if links:
        merged = {u.url: u for u in att.urls}
        for info in collect_urls(links):
            if info.url in merged:
                merged[info.url].sources = list(dict.fromkeys(merged[info.url].sources + info.sources))
            else:
                merged[info.url] = info
        att.urls = list(merged.values())


def extract_onenote(data: bytes) -> list[EmbeddedObject]:
    out = []
    pos = 0
    while len(out) < 50:
        pos = data.find(ONENOTE_FILE_GUID, pos)
        if pos < 0 or pos + 36 > len(data):
            break
        size = struct.unpack_from("<Q", data, pos + 16)[0]
        start = pos + 36
        blob = data[start:start + min(size, len(data) - start)]
        t = ft.detect(blob)
        detected = t.id if t else None
        if detected is None:
            head = blob[:4096].decode("latin-1", "replace").lower()
            if re.search(r"<hta:application|<script|wscript|powershell|@echo off|cmd /c", head):
                detected = "script"
        out.append(EmbeddedObject(f"onenote@{pos}", None, len(blob), hashlib.sha256(blob).hexdigest(), detected))
        pos = start + max(1, len(blob))
    return out


# --------------------------------------------------------------------------- findings

_RISKY_TYPES = {"pe", "elf", "macho", "lnk", "script", "html", "svg", "onenote", "chm", "jar", "iso", "vhd", "vhdx"}
_RISKY_NAME = re.compile(r"\.(?:exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|lnk|dll|cpl|jar|msi|reg)$", re.I)


def _embedded_findings(objects: list[EmbeddedObject], label: str, ev: dict, code: str) -> list[Finding]:
    if not objects:
        return []
    risky = [o for o in objects if o.detected_type in _RISKY_TYPES or (o.name and _RISKY_NAME.search(o.name))]
    names = [o.name or o.detected_type or o.source for o in (risky or objects)][:MAX_EXAMPLES]
    return [Finding(code, Severity.HIGH if risky else Severity.MEDIUM,
                    f"{label} embeds {len(objects)} file(s){' including risky ones' if risky else ''}: "
                    f"{', '.join(map(str, names[:3]))}.",
                    {**ev, "embedded": [vars(o) for o in objects[:MAX_EXAMPLES]]})]


def _office_findings(o: OfficeAnalysis, label: str, ev: dict) -> list[Finding]:
    out: list[Finding] = []
    if o.metadata:
        out.append(Finding("DOC_METADATA", Severity.INFO,
                           f"{label} metadata: " + ", ".join(f"{k}={v}" for k, v in list(o.metadata.items())[:6]),
                           {**ev, "metadata": o.metadata}))
    if o.vba:
        autoexec = sorted({a for m in o.vba for a in m.autoexec})
        # Keep vba.SUSPICIOUS order: the most telling behaviours come first.
        suspicious = list(dict.fromkeys(s for m in o.vba for s in m.suspicious))
        mev = {**ev, "modules": [m.name for m in o.vba], "autoexec": autoexec, "suspicious": suspicious,
               "iocs": sorted({i for m in o.vba for i in m.iocs})[:20]}
        if autoexec and suspicious:
            what = ", ".join(x.split(": ", 1)[-1] for x in suspicious[:3])
            out.append(Finding("MACRO_MALICIOUS_PATTERN", Severity.HIGH,
                               f"{label} has VBA that runs automatically ({', '.join(autoexec)}) and {what}.", mev))
        elif autoexec:
            out.append(Finding("MACRO_AUTOEXEC", Severity.MEDIUM,
                               f"{label} has VBA that runs automatically ({', '.join(autoexec)}).", mev))
        elif suspicious:
            out.append(Finding("MACRO_SUSPICIOUS", Severity.MEDIUM,
                               f"{label} has VBA with suspicious calls ({len(suspicious)}).", mev))
        stomped = [m.name for m in o.vba if m.stomped]
        if stomped:
            out.append(Finding("MACRO_STOMPED", Severity.HIGH,
                               f"{label}: VBA source is missing but compiled code remains (VBA stomping): "
                               f"{', '.join(stomped)}.", {**ev, "modules": stomped}))
    if o.xlm_macros:
        out.append(Finding("MACRO_XLM", Severity.HIGH,
                           f"{label} contains Excel 4.0 (XLM) macro sheets"
                           f"{' that auto-run' if o.xlm_autoexec else ''}.", {**ev, "formulas": o.xlm_macros[:MAX_EXAMPLES]}))
    if o.dde:
        out.append(Finding("DOC_DDE", Severity.HIGH,
                           f"{label} uses DDE fields that can run commands when opened.", {**ev, "fields": o.dde}))
    if o.activex:
        out.append(Finding("DOC_ACTIVEX", Severity.MEDIUM, f"{label} contains ActiveX controls.",
                           {**ev, "parts": o.activex[:MAX_EXAMPLES]}))
    dangerous = [e for e in o.external if e["type"] in ("oleObject", "frame", "subDocument", "externalLinkPath",
                                                         "package", "control")]
    if dangerous:
        out.append(Finding("DOC_EXTERNAL_OBJECT", Severity.HIGH,
                           f"{label} loads objects from external locations when opened: "
                           f"{', '.join(e['target'] for e in dangerous[:3])}.", {**ev, "external": dangerous[:MAX_EXAMPLES]}))
    images = [e for e in o.external if e["type"] == "image"]
    if images:
        out.append(Finding("DOC_REMOTE_IMAGE", Severity.LOW,
                           f"{label} references remote images (open tracking or NTLM leaks via UNC paths).",
                           {**ev, "external": images[:MAX_EXAMPLES]}))
    unc = [e for e in o.external if e["target"].startswith(("\\\\", "file://"))]
    if unc:
        out.append(Finding("DOC_UNC_PATH", Severity.HIGH,
                           f"{label} references UNC/file paths, which can leak Windows credentials (NTLM hashes).",
                           {**ev, "external": unc[:MAX_EXAMPLES]}))
    for cls in o.rtf_object_classes:
        desc = RTF_EXPLOIT_CLASSES.get(cls.lower())
        if desc and cls.lower() not in ("package", "word.document.8"):
            out.append(Finding("RTF_EXPLOIT_CLASS", Severity.HIGH,
                               f"{label} embeds an OLE object of class {cls}: {desc}.", {**ev, "class": cls}))
    out += _embedded_findings(o.embedded, label, ev, "DOC_EMBEDDED_OBJECT")
    return out


def _pdf_findings(p: PdfAnalysis, label: str, ev: dict) -> list[Finding]:
    out: list[Finding] = []
    k = p.keywords
    pev = {**ev, "keywords": k}
    js = k.get("JS", 0) + k.get("JavaScript", 0)
    auto = k.get("OpenAction", 0) + k.get("AA", 0)
    if js:
        out.append(Finding("PDF_JAVASCRIPT", Severity.HIGH,
                           f"{label} contains JavaScript{' that runs on open' if auto else ''}"
                           f"{' (' + ', '.join(p.javascript_markers[:4]) + ')' if p.javascript_markers else ''}.",
                           {**pev, "snippets": p.javascript[:3], "markers": p.javascript_markers}))
    if p.launch or k.get("Launch"):
        out.append(Finding("PDF_LAUNCH", Severity.HIGH,
                           f"{label} has a Launch action that starts a program"
                           f"{': ' + p.launch[0] if p.launch else ''}.", {**pev, "launch": p.launch}))
    if auto and not js and not p.launch:
        out.append(Finding("PDF_AUTO_ACTION", Severity.MEDIUM,
                           f"{label} performs an action automatically when opened (/OpenAction or /AA).", pev))
    if p.embedded or k.get("EmbeddedFile") or k.get("EmbeddedFiles"):
        objs = list(p.embedded)
        for i, name in enumerate(p.embedded_names):
            if i < len(objs):
                objs[i].name = objs[i].name or name
            else:  # file spec seen but its stream was not decodable
                objs.append(EmbeddedObject("pdf:/Filespec", name, 0, "", None))
        if not objs:
            objs = [EmbeddedObject("pdf:/EmbeddedFile", None, 0, "", None)]
        out += _embedded_findings(objs, label, ev, "PDF_EMBEDDED_FILE")
    if k.get("SubmitForm") or k.get("ImportData"):
        out.append(Finding("PDF_SUBMIT_FORM", Severity.MEDIUM,
                           f"{label} contains a form that submits data to a server.", pev))
    if k.get("GoToR") or k.get("GoToE"):
        out.append(Finding("PDF_REMOTE_GOTO", Severity.MEDIUM, f"{label} opens a remote or embedded document.", pev))
    if k.get("RichMedia"):
        out.append(Finding("PDF_RICHMEDIA", Severity.MEDIUM, f"{label} embeds rich media (Flash/3D).", pev))
    if k.get("XFA"):
        out.append(Finding("PDF_XFA", Severity.LOW, f"{label} uses XFA forms (scriptable).", pev))
    if k.get("Encrypt"):
        out.append(Finding("PDF_ENCRYPTED", Severity.LOW,
                           f"{label} is encrypted; streams could not all be inspected.", pev))
    if p.obfuscated_names:
        out.append(Finding("PDF_OBFUSCATED_NAMES", Severity.MEDIUM,
                           f"{label} hides PDF keywords with #-escapes: {', '.join(p.obfuscated_names[:3])}.",
                           {**pev, "names": p.obfuscated_names}))
    if p.uris:
        out.append(Finding("PDF_LINKS", Severity.INFO, f"{label} links to {len(p.uris)} URL(s).",
                           {**ev, "uris": p.uris[:MAX_EXAMPLES]}))
    if p.truncated:
        out.append(Finding("PDF_TRUNCATED", Severity.LOW, f"{label}: PDF analysis stopped at a safety limit.", ev))
    return out


def _lnk_findings(lnk: LnkInfo, label: str, ev: dict) -> list[Finding]:
    out: list[Finding] = []
    lev = {**ev, **{k: v for k, v in vars(lnk).items() if v}}
    command = " ".join(filter(None, [lnk.target, lnk.env_target, lnk.relative_path, lnk.arguments]))
    m = _LOLBINS.search(command)
    if m:
        out.append(Finding("LNK_RUNS_COMMAND", Severity.HIGH,
                           f"{label} is a shortcut that runs {m.group(0)}: {command[:200]}.", lev))
    if lnk.arguments and (len(lnk.arguments) > 260 or re.search(r"\s{40,}", lnk.arguments)):
        out.append(Finding("LNK_LONG_ARGUMENTS", Severity.MEDIUM,
                           f"{label} has {len(lnk.arguments)} characters of arguments (padding hides them in "
                           "the Properties dialog).", lev))
    if lnk.icon and _DOC_ICONS.search(lnk.icon):
        out.append(Finding("LNK_ICON_DISGUISE", Severity.MEDIUM,
                           f"{label} borrows a document-style icon ({lnk.icon}) to look harmless.", lev))
    if lnk.show_command and lnk.show_command.startswith("minimized"):
        out.append(Finding("LNK_HIDDEN_WINDOW", Severity.MEDIUM, f"{label} runs with its window minimized.", lev))
    if lnk.machine_id:
        out.append(Finding("LNK_MACHINE_ID", Severity.INFO,
                           f"{label} was created on a machine named '{lnk.machine_id}'.", lev))
    return out


def _script_findings(s: ScriptAnalysis, label: str, ev: dict) -> list[Finding]:
    out: list[Finding] = []
    sev = {**ev, "indicators": s.indicators, "urls": s.urls[:MAX_EXAMPLES], "decoded": s.decoded_commands[:2]}
    if "downloader" in s.indicators and "execution" in s.indicators:
        out.append(Finding("SCRIPT_DOWNLOADER", Severity.HIGH,
                           f"{label} downloads and runs code ({', '.join(s.indicators['downloader'][:2])}).", sev))
    elif s.indicators.get("execution") or s.indicators.get("downloader"):
        out.append(Finding("SCRIPT_EXECUTION", Severity.MEDIUM,
                           f"{label} runs commands ({', '.join((s.indicators.get('execution') or s.indicators['downloader'])[:3])}).", sev))
    if s.indicators.get("obfuscation") or s.encoded_script or s.long_base64:
        what = "encoded with JScript/VBScript.Encode" if s.encoded_script else \
            ", ".join(s.indicators.get("obfuscation", [])[:3]) or f"{s.long_base64} long base64 blob(s)"
        out.append(Finding("SCRIPT_OBFUSCATED", Severity.MEDIUM, f"{label} is obfuscated ({what}).", sev))
    for name, code in (("persistence", "SCRIPT_PERSISTENCE"), ("defense evasion", "SCRIPT_DEFENSE_EVASION"),
                       ("ransomware", "SCRIPT_RANSOMWARE")):
        if s.indicators.get(name):
            out.append(Finding(code, Severity.HIGH,
                               f"{label} shows {name} behaviour ({', '.join(s.indicators[name][:3])}).", sev))
    if s.decoded_commands:
        out.append(Finding("SCRIPT_ENCODED_COMMAND", Severity.HIGH,
                           f"{label} carries a base64-encoded PowerShell command: {s.decoded_commands[0][:150]}.", sev))
    return out
