"""File type detection from content (magic bytes) and extension classification.

The declared MIME type and the filename are chosen by the sender; only the bytes
are evidence. Detection here is deliberately conservative: it returns None
rather than guess.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass


@dataclass(frozen=True)
class FileType:
    id: str
    description: str
    extensions: frozenset[str]  # extensions a benign file of this type would normally use
    category: str  # "executable", "document", "archive", "disk-image", "html", "image", "text", ...


def _t(id, desc, exts, cat):
    return FileType(id, desc, frozenset(exts.split()), cat)


PE = _t("pe", "Windows executable (PE)", "exe dll scr com sys cpl ocx drv efi msstyles mui ax xll", "executable")
ELF = _t("elf", "Linux executable (ELF)", "elf so bin o", "executable")
MACHO = _t("macho", "macOS executable (Mach-O)", "dylib bundle macho", "executable")
PDF = _t("pdf", "PDF document", "pdf", "document")
RTF = _t("rtf", "Rich Text Format", "rtf doc", "document")
OLE = _t("ole", "OLE compound file (legacy Office/MSI/MSG)",
         "doc dot xls xlt xla ppt pps pot msi msg pub vsd mpp", "document")
OOXML_WORD = _t("docx", "Word document (OOXML)", "docx docm dotx dotm", "document")
OOXML_EXCEL = _t("xlsx", "Excel workbook (OOXML)", "xlsx xlsm xltx xltm xlam xlsb", "document")
OOXML_PPT = _t("pptx", "PowerPoint (OOXML)", "pptx pptm potx potm ppsx ppsm ppam", "document")
ODF = _t("odf", "OpenDocument", "odt ods odp odg", "document")
JAR = _t("jar", "Java archive", "jar", "executable")
APK = _t("apk", "Android package", "apk", "executable")
ZIP = _t("zip", "ZIP archive", "zip", "archive")
RAR = _t("rar", "RAR archive", "rar", "archive")
SEVENZ = _t("7z", "7-Zip archive", "7z", "archive")
GZIP = _t("gzip", "gzip data", "gz tgz", "archive")
BZIP2 = _t("bzip2", "bzip2 data", "bz2 tbz2", "archive")
XZ = _t("xz", "xz data", "xz txz", "archive")
CAB = _t("cab", "Microsoft Cabinet", "cab", "archive")
ACE = _t("ace", "ACE archive", "ace", "archive")
TAR = _t("tar", "tar archive", "tar", "archive")
ISO = _t("iso", "ISO 9660 disk image", "iso img", "disk-image")
VHD = _t("vhd", "Virtual hard disk (VHD)", "vhd", "disk-image")
VHDX = _t("vhdx", "Virtual hard disk (VHDX)", "vhdx", "disk-image")
LNK = _t("lnk", "Windows shortcut (LNK)", "lnk", "executable")
ONENOTE = _t("onenote", "OneNote document", "one onepkg", "document")
CHM = _t("chm", "Compiled HTML Help", "chm", "executable")
PNG = _t("png", "PNG image", "png", "image")
JPEG = _t("jpeg", "JPEG image", "jpg jpeg jpe jfif", "image")
GIF = _t("gif", "GIF image", "gif", "image")
BMP = _t("bmp", "BMP image", "bmp dib", "image")
WEBP = _t("webp", "WebP image", "webp", "image")
TIFF = _t("tiff", "TIFF image", "tif tiff", "image")
ICO = _t("ico", "Windows icon", "ico cur", "image")
SVG = _t("svg", "SVG image (can contain script)", "svg svgz", "html")
HTML = _t("html", "HTML document", "html htm xhtml shtml mht mhtml hta", "html")
EML = _t("eml", "Email message", "eml msg txt", "message")
SHEBANG = _t("script", "Script with #! interpreter line", "sh bash py pl rb", "executable")

# Extensions that execute code (or launch something that does) when double-clicked on Windows.
EXECUTABLE_EXTENSIONS = frozenset("""
    exe scr com pif cpl dll msi msix msixbundle appx appxbundle msp mst bat cmd ps1 ps1xml psm1 psd1
    vbs vbe js jse wsf wsh wsc hta jar lnk reg scf url application gadget msc inf sct xll xla xlam
    iqy slk settingcontent-ms chm hlp library-ms search-ms appref-ms website diagcab cpl apk
    sh command app elf run mde accde ade adp
""".split())
DISK_IMAGE_EXTENSIONS = frozenset("iso img vhd vhdx dmg udf".split())
MACRO_EXTENSIONS = frozenset("docm dotm xlsm xltm xlam xlsb pptm potm ppsm ppam sldm".split())
HTML_EXTENSIONS = frozenset("html htm xhtml shtml mht mhtml svg svgz hta".split())
ONENOTE_EXTENSIONS = frozenset("one onepkg".split())
ARCHIVE_EXTENSIONS = frozenset("zip rar 7z gz tgz tar bz2 tbz2 xz txz cab ace arj lzh lha z zipx r00".split())
# Extensions a lure pretends to be in "invoice.pdf.exe".
DOCUMENT_EXTENSIONS = frozenset("""
    pdf doc docx xls xlsx ppt pptx txt rtf csv odt ods jpg jpeg png gif bmp mp3 mp4 wav avi mov html htm
    zip rar eml msg
""".split())

_ISO_OFFSETS = (0x8001, 0x8801, 0x9001)
_HTML_RE = re.compile(rb"^\s*(?:<!--.*?-->\s*)*<(?:!doctype\s+html|html|head|body|script|meta|iframe)[\s>]", re.I | re.S)
_SVG_RE = re.compile(rb"^\s*(?:<\?xml[^>]*>\s*)?(?:<!--.*?-->\s*)*(?:<!doctype\s+svg[^>]*>\s*)?<svg[\s>]", re.I | re.S)
_EML_RE = re.compile(rb"^(?:(?:Received|Return-Path|From|To|Subject|Date|Message-ID|MIME-Version|Delivered-To):[^\n]*\r?\n){2}", re.I)


def extension_of(filename: str | None) -> str | None:
    if not filename or "." not in filename:
        return None
    ext = filename.rsplit(".", 1)[1].strip().lower()
    return ext or None


def detect(data: bytes) -> FileType | None:
    """Identify the file type from its leading bytes."""
    head = data[:64]
    if head.startswith(b"MZ") and _is_pe(data):
        return PE
    if head.startswith(b"\x7fELF"):
        return ELF
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return MACHO
    if b"%PDF-" in data[:1024]:  # readers accept the header anywhere in the first 1 KB
        return PDF
    if head.startswith(b"{\\rt"):  # Word opens "{\rt" as RTF; malware drops the "f"
        return RTF
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return OLE
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return _zip_subtype(data)
    if head.startswith(b"Rar!\x1a\x07"):
        return RAR
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return SEVENZ
    if head.startswith(b"\x1f\x8b"):
        return GZIP
    if head.startswith(b"BZh") and head[3:4].isdigit():
        return BZIP2
    if head.startswith(b"\xfd7zXZ\x00"):
        return XZ
    if head.startswith(b"MSCF"):
        return CAB
    if head[7:14] == b"**ACE**":
        return ACE
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F"):
        return LNK
    if head.startswith(b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3"):
        return ONENOTE
    if head.startswith(b"ITSF"):
        return CHM
    if head.startswith(b"conectix") or data[-512:].startswith(b"conectix"):
        return VHD
    if head.startswith(b"vhdxfile"):
        return VHDX
    if any(data[o:o + 5] == b"CD001" for o in _ISO_OFFSETS):
        return ISO
    if len(data) > 262 and data[257:262] == b"ustar":
        return TAR
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return PNG
    if head.startswith(b"\xff\xd8\xff"):
        return JPEG
    if head.startswith((b"GIF87a", b"GIF89a")):
        return GIF
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return WEBP
    if head.startswith((b"II*\x00", b"MM\x00*")):
        return TIFF
    if head.startswith(b"BM") and len(data) > 14 and int.from_bytes(data[2:6], "little") == len(data):
        return BMP
    if head.startswith(b"\x00\x00\x01\x00") and 0 < int.from_bytes(data[4:6], "little") <= 64:
        return ICO
    if head.startswith(b"#!"):
        return SHEBANG

    text = _text_head(data)
    if text is not None:
        if _SVG_RE.match(text):
            return SVG
        if _HTML_RE.match(text):
            return HTML
        if _EML_RE.match(text):
            return EML
    return None


def _text_head(data: bytes) -> bytes | None:
    """First 4 KB as ASCII-compatible bytes, decoding UTF-16 and stripping a BOM."""
    head = data[:4096]
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return head.decode("utf-16").encode("utf-8", "ignore")
        except UnicodeDecodeError:
            return None
    return head.removeprefix(b"\xef\xbb\xbf")


def _is_pe(data: bytes) -> bool:
    if len(data) < 0x40:
        return False
    offset = int.from_bytes(data[0x3C:0x40], "little")
    # A bare "MZ" with no PE header is still a DOS executable; treat both as executables.
    return data[offset:offset + 4] == b"PE\x00\x00" if offset + 4 <= len(data) else True


def _zip_subtype(data: bytes) -> FileType:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist()[:5000])
            if "mimetype" in names:
                try:
                    if (zf.getinfo("mimetype").file_size < 200
                            and zf.read("mimetype").startswith(b"application/vnd.oasis.opendocument")):
                        return ODF
                except Exception:
                    pass
    except Exception:
        return ZIP
    if "[Content_Types].xml" in names:
        if any(n.startswith("word/") for n in names):
            return OOXML_WORD
        if any(n.startswith("xl/") for n in names):
            return OOXML_EXCEL
        if any(n.startswith("ppt/") for n in names):
            return OOXML_PPT
    if "AndroidManifest.xml" in names and "classes.dex" in names:
        return APK
    if "META-INF/MANIFEST.MF" in names:
        return JAR
    return ZIP
