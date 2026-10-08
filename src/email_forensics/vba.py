"""VBA macro extraction (MS-OVBA) and static keyword analysis.

Finds VBA projects inside a compound file (Word ``Macros/VBA``, Excel
``_VBA_PROJECT_CUR/VBA``, a bare ``vbaProject.bin``), decompresses each module's
source and flags auto-execution entry points, suspicious calls and IOCs, in the
spirit of oletools' olevba. Code is never executed.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field

from .cfb import CompoundFile

MAX_MODULES = 500
MAX_SOURCE = 2_000_000
PREVIEW_CHARS = 4000

AUTOEXEC = (
    "AutoOpen", "AutoExec", "AutoClose", "AutoNew", "AutoExit", "Auto_Open", "Auto_Close", "Auto_Activate",
    "Document_Open", "Document_Close", "Document_New", "Document_ContentControlOnEnter", "DocumentOpen",
    "Workbook_Open", "Workbook_Activate", "Workbook_BeforeClose", "Workbook_Deactivate", "Workbook_SheetActivate",
    "Worksheet_Change", "Worksheet_Activate", "Presentation_Open", "AutoOpenCmd",
    "InkPicture1_Painted", "Frame1_Layout", "UserForm_Initialize", "UserForm_Activate",
)
# (pattern, description) -- word-bounded, case-insensitive.
SUSPICIOUS = (
    (r"Shell|ShellExecute|WScript\.Shell|Shell\.Application|\.Exec\b|\.Run\b", "runs a program or command"),
    (r"CreateObject|GetObject", "instantiates a COM object"),
    (r"powershell|cmd(?:\.exe)?\s*/c|mshta|wscript|cscript|regsvr32|rundll32|certutil|bitsadmin|schtasks",
     "launches a living-off-the-land binary"),
    (r"URLDownloadToFile|XMLHTTP|WinHttp|ServerXMLHTTP|InternetOpen|Net\.WebClient|DownloadFile|DownloadString",
     "downloads from the internet"),
    (r"ADODB\.Stream|SaveToFile|Open\s+\S+\s+For\s+(?:Binary|Output|Append)|\bPut\s+#|Scripting\.FileSystemObject",
     "writes files"),
    (r"Declare\s+(?:PtrSafe\s+)?(?:Function|Sub)\b[^\n]*\bLib\b", "calls Windows API functions"),
    (r"VirtualAlloc|RtlMoveMemory|CreateThread|WriteProcessMemory|EnumSystemLocales|CallWindowProc",
     "manipulates memory (shellcode injection)"),
    (r"ExecuteExcel4Macro|MacScript|Application\.Run|CallByName", "runs code indirectly"),
    (r"Environ\s*\(|\bKill\b|DeleteFile|\.Delete\b", "reads environment / deletes files"),
    (r"(?:Chr[WB]?\$?\s*\(\s*\d+\s*\)\s*&\s*){5,}", "builds strings character by character (obfuscation)"),
    (r"StrReverse|Base64|FromBase64String|\bReplace\s*\(", "decodes or deobfuscates strings"),
    (r"VBProject|VBComponents|CodeModule|AccessVBOM", "modifies VBA code (self-replication / persistence)"),
)
_SUSPICIOUS = [(re.compile(rf"\b(?:{p})", re.I), d) for p, d in SUSPICIOUS]
_AUTOEXEC_RE = re.compile(r"\b(?:Sub|Function)\s+(" + "|".join(AUTOEXEC) + r")\b", re.I)
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>)]+", re.I)
_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_EXE_RE = re.compile(r"[\w\-. ]+\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js|hta|jar|msi|lnk)\b", re.I)


class VbaError(ValueError):
    pass


def decompress(data: bytes) -> bytes:
    """MS-OVBA 2.4.1 decompression."""
    if not data or data[0] != 0x01:
        raise VbaError("bad compressed container signature")
    out = bytearray()
    pos = 1
    while pos + 2 <= len(data):
        header = struct.unpack_from("<H", data, pos)[0]
        size = (header & 0x0FFF) + 3
        compressed = header & 0x8000
        chunk_end = min(pos + size, len(data))
        pos += 2
        chunk_start = len(out)
        if not compressed:
            out += data[pos:pos + 4096]
            pos = chunk_end
            continue
        while pos < chunk_end:
            flags = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if not flags & (1 << bit):
                    out.append(data[pos])
                    pos += 1
                    continue
                if pos + 2 > chunk_end:
                    raise VbaError("truncated copy token")
                token = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                done = len(out) - chunk_start
                bit_count = max((done - 1).bit_length(), 4) if done > 0 else 4
                length_mask = 0xFFFF >> bit_count
                offset = (token >> (16 - bit_count)) + 1
                length = (token & length_mask) + 3
                if offset > done:
                    raise VbaError("copy token points before chunk start")
                for _ in range(length):
                    out.append(out[-offset])
        if len(out) > MAX_SOURCE:
            raise VbaError("decompressed data too large")
    return bytes(out)


@dataclass
class VbaModule:
    name: str
    stream: str
    code_bytes: int = 0
    sha256: str | None = None
    preview: str = ""
    autoexec: list[str] = field(default_factory=list)
    suspicious: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    stomped: bool = False  # compiled p-code present but source missing (VBA stomping)


def _parse_dir(data: bytes) -> tuple[int, list[tuple[str, str, int]]]:
    """Return (codepage, [(module name, stream name, text offset)])."""
    codepage, modules = 1252, []
    current: dict | None = None
    pos = 0
    while pos + 6 <= len(data) and len(modules) < MAX_MODULES:
        rid, size = struct.unpack_from("<HI", data, pos)
        pos += 6
        if rid == 0x0009:  # PROJECTVERSION: Size field is 4 but 6 bytes follow
            size = 6
        value = data[pos:pos + size]
        pos += size
        if rid == 0x0003 and len(value) >= 2:
            codepage = struct.unpack_from("<H", value)[0]
        elif rid == 0x0019:
            current = {"name": value, "stream": value, "offset": 0}
        elif current is not None and rid == 0x001A:
            current["stream"] = value
        elif current is not None and rid == 0x0031 and len(value) >= 4:
            current["offset"] = struct.unpack_from("<I", value)[0]
        elif current is not None and rid == 0x002B:
            modules.append((current["name"], current["stream"], current["offset"]))
            current = None
        elif rid == 0x0010:  # dir terminator
            break
    enc = _codec(codepage)
    return codepage, [(n.decode(enc, "replace"), s.decode(enc, "replace"), off) for n, s, off in modules]


def _codec(codepage: int) -> str:
    name = {65001: "utf-8", 1200: "utf-16-le", 10000: "mac_roman"}.get(codepage, f"cp{codepage}")
    try:
        "".encode(name)
        return name
    except LookupError:
        return "cp1252"


def analyze_source(code: str) -> tuple[list[str], list[str], list[str]]:
    autoexec = sorted({m.group(1) for m in _AUTOEXEC_RE.finditer(code)}, key=str.lower)
    suspicious = []
    for regex, description in _SUSPICIOUS:
        m = regex.search(code)
        if m:
            suspicious.append(f"{m.group(0).strip()[:40]}: {description}")
    iocs = sorted(set(_URL_RE.findall(code)) | set(_IP_RE.findall(code)) | {e.strip() for e in _EXE_RE.findall(code)})
    return autoexec, suspicious, iocs[:50]


def vba_roots(cf: CompoundFile) -> list[tuple[str, ...]]:
    """Storages that contain a VBA project (their 'VBA/dir' stream exists)."""
    roots = []
    for entry in cf.streams():
        if len(entry.path) >= 2 and entry.path[-1].lower() == "dir" and entry.path[-2].lower() == "vba":
            roots.append(entry.path[:-2])
    return roots


def extract_vba(cf: CompoundFile) -> list[VbaModule]:
    modules: list[VbaModule] = []
    for root in vba_roots(cf):
        try:
            dir_data = decompress(cf.read_path(*root, "VBA", "dir") or b"")
        except (VbaError, ValueError):
            continue
        codepage, entries = _parse_dir(dir_data)
        enc = _codec(codepage)
        for name, stream_name, offset in entries:
            stream_path = "/".join((*root, "VBA", stream_name))
            try:
                raw = cf.read_path(*root, "VBA", stream_name)
            except ValueError:  # corrupt sector chain (CfbError)
                raw = None
            mod = VbaModule(name=name, stream=stream_path)
            if raw is None:
                modules.append(mod)
                continue
            try:
                source = decompress(raw[offset:]) if offset < len(raw) else b""
            except VbaError:
                source = b""
            code = source.decode(enc, "replace")
            mod.code_bytes = len(source)
            mod.sha256 = hashlib.sha256(source).hexdigest()
            body = "\n".join(line for line in code.splitlines() if not line.startswith("Attribute VB_"))
            mod.preview = body.strip()[:PREVIEW_CHARS]
            mod.autoexec, mod.suspicious, mod.iocs = analyze_source(code)
            # p-code lives before the source; a large module stream with almost no
            # source suggests the source was wiped while compiled code remains.
            mod.stomped = offset > 2048 and len(body.strip()) < 20
            modules.append(mod)
    return modules
