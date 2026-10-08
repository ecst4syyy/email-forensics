"""Static attachment analysis: true type, hashes, risky formats, filename tricks, archives.

Attachments are never executed, rendered or opened with external programs.
"""

from __future__ import annotations

import hashlib
import io
import re
import json
import os
import zipfile
from email.utils import collapse_rfc2231_value
from pathlib import Path

from . import filetype as ft
from .archives import inspect_archive, is_bomb
from .html_analysis import analyze_html, html_findings
from .mime import MimeTree, WalkedPart, decode_text
from .models import ArchiveInfo, Attachment, Finding, Severity
from .payloads import analyze_payload
from .textcheck import invisible_char_findings, safe_display
from .urls import collect_urls, url_findings

BODY_TYPES = ("text/plain", "text/html")
MAX_EXAMPLES = 10

# Declared Content-Type → detected type ids that are consistent with it.
_DECLARED_EXPECT = {
    "application/pdf": {"pdf"},
    "application/zip": {"zip", "docx", "xlsx", "pptx", "odf", "jar", "apk"},
    "application/x-zip-compressed": {"zip", "docx", "xlsx", "pptx", "odf", "jar", "apk"},
    "application/msword": {"ole", "rtf", "docx"},
    "application/vnd.ms-excel": {"ole", "xlsx"},
    "application/vnd.ms-powerpoint": {"ole", "pptx"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {"docx", "zip"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {"xlsx", "zip"},
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {"pptx", "zip"},
    "application/rtf": {"rtf"},
    "text/rtf": {"rtf"},
}

# HTML smuggling: the page assembles a file in the browser and "downloads" it,
# bypassing gateway scanners that only look at the email.
_SMUGGLING_RE = re.compile(
    r"atob\s*\(|new\s+Blob\s*\(|msSaveOrOpenBlob|createObjectURL|\.download\s*=|"
    r"fromCharCode|unescape\s*\(|document\.write\s*\(",
    re.I,
)
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{4000,}={0,2}")
_REMOTE_TEMPLATE_RE = re.compile(rb"attachedTemplate[^>]*TargetMode=\"External\"|TargetMode=\"External\"[^>]*attachedTemplate", re.I)


_PASSWORD_HINT_RE = re.compile(
    r"\b(?:pass(?:word|wd|code|phrase)?|pwd|kennwort|passwort|contrase(?:ñ|n)a|mot de passe|senha|"
    r"parola|wachtwoord|hasło|haslo)\b|пароль|密码|密碼|パスワード",
    re.I,
)


def correlate_with_body(findings: list[Finding], body_texts: list[str]) -> None:
    """Raise encrypted-archive findings to HIGH when the body appears to give the password."""
    if not any(f.code == "ATT_ENCRYPTED_ARCHIVE" for f in findings):
        return
    hint = next((m for t in body_texts if (m := _PASSWORD_HINT_RE.search(t))), None)
    if not hint:
        return
    for f in findings:
        if f.code == "ATT_ENCRYPTED_ARCHIVE":
            f.severity = Severity.HIGH
            f.message += " The message body mentions a password, a common way to deliver malware past scanners."
            f.evidence["body_password_hint"] = hint.group(0)


def is_attachment_part(part: WalkedPart) -> bool:
    info = part.info
    return info.is_attachment or info.content_type not in BODY_TYPES


def analyze_attachments(tree: MimeTree) -> tuple[list[Attachment], list[Finding]]:
    attachments: list[Attachment] = []
    findings: list[Finding] = []
    for leaf in tree.leaves:
        if not is_attachment_part(leaf):
            continue
        att, att_findings = _analyze_one(leaf)
        attachments.append(att)
        findings += att_findings
    return attachments, findings


def _analyze_one(leaf: WalkedPart) -> tuple[Attachment, list[Finding]]:
    info, data = leaf.info, leaf.payload
    detected = ft.detect(data)
    att = Attachment(
        part=info.path,
        filename=info.filename,
        content_type=info.content_type,
        inline=not info.is_attachment,
        size=len(data),
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        extension=ft.extension_of(info.filename),
        detected_type=detected.id if detected else None,
        detected_description=detected.description if detected else None,
    )
    label = f"Attachment '{safe_display(info.filename)}'" if info.filename else f"Attachment part {info.path}"
    ev = {"part": info.path, "filename": info.filename, "sha256": att.sha256}

    findings = _filename_findings(leaf, label, ev)
    findings += _risk_findings(att, detected, data, label, ev)
    findings += _type_mismatch_findings(att, detected, label, ev)
    att.payload, payload_findings = analyze_payload(att, data, label)
    findings += payload_findings
    if detected and (detected.category == "archive" or detected.id in ("jar", "apk")):
        att.archive = inspect_archive(data, detected)
        findings += _archive_findings(att.archive, len(data), label, ev)
    return att, findings


def _filename_findings(leaf: WalkedPart, label: str, ev: dict) -> list[Finding]:
    name = leaf.info.filename
    out: list[Finding] = []
    if not name:
        return out
    out += invisible_char_findings(f"{label} filename", name, prominent=True)

    if "/" in name or "\\" in name or name.startswith(".."):
        out.append(Finding("ATT_FILENAME_PATH", Severity.MEDIUM,
                           f"{label} has path characters in its name (path traversal against extraction tools).", ev))

    labels = [p.strip() for p in name.lower().split(".")]
    if len(labels) >= 3 and labels[-2] in ft.DOCUMENT_EXTENSIONS and _is_risky_extension(labels[-1]):
        out.append(Finding("ATT_DOUBLE_EXTENSION", Severity.HIGH,
                           f"{label} disguises a .{labels[-1]} file as .{labels[-2]}.", ev))
    if re.search(r"(?:\s{3,}|_{5,})\.\w+$", name):
        out.append(Finding("ATT_FILENAME_PADDING", Severity.MEDIUM,
                           f"{label} pads its name with whitespace/underscores to push the real extension out of view.", ev))

    # Content-Type "name" and Content-Disposition "filename" can disagree; different
    # clients and scanners pick different ones.
    try:
        ct_name = leaf.message.get_param("name")
        cd_name = leaf.message.get_param("filename", header="content-disposition")
    except Exception:
        ct_name = cd_name = None
    ct_name, cd_name = _param_text(ct_name), _param_text(cd_name)
    if ct_name and cd_name and ct_name != cd_name:
        out.append(Finding("ATT_FILENAME_CONFLICT", Severity.MEDIUM,
                           f"{label}: Content-Type name '{safe_display(ct_name)}' differs from Content-Disposition "
                           f"filename '{safe_display(cd_name)}'.", {**ev, "content_type_name": ct_name, "disposition_filename": cd_name}))
    return out


def _param_text(value) -> str | None:
    """Collapse an RFC 2231 parameter (which may be a (charset, lang, value) tuple) to text."""
    if value is None:
        return None
    try:
        return str(collapse_rfc2231_value(value)).strip()
    except Exception:
        return str(value).strip()


def _is_risky_extension(ext: str) -> bool:
    return (ext in ft.EXECUTABLE_EXTENSIONS or ext in ft.DISK_IMAGE_EXTENSIONS
            or ext in ft.HTML_EXTENSIONS or ext in ft.ONENOTE_EXTENSIONS or ext in ft.MACRO_EXTENSIONS)


def _risk_findings(att: Attachment, detected: ft.FileType | None, data: bytes,
                   label: str, ev: dict) -> list[Finding]:
    out: list[Finding] = []
    ext = att.extension or ""
    category = detected.category if detected else None
    ev = {**ev, "detected_type": att.detected_type}

    if ext in ft.EXECUTABLE_EXTENSIONS or category == "executable":
        what = detected.description if category == "executable" else f".{ext} file"
        out.append(Finding("ATT_EXECUTABLE", Severity.HIGH, f"{label} is executable ({what}).", ev))
    if ext in ft.DISK_IMAGE_EXTENSIONS or category == "disk-image":
        out.append(Finding("ATT_DISK_IMAGE", Severity.HIGH,
                           f"{label} is a disk image; its contents bypass Mark-of-the-Web protections.", ev))
    if ext in ft.ONENOTE_EXTENSIONS or att.detected_type == ft.ONENOTE.id:
        out.append(Finding("ATT_ONENOTE", Severity.HIGH,
                           f"{label} is a OneNote file, a common vehicle for embedded scripts.", ev))
    if ext in ft.HTML_EXTENSIONS or category == "html":
        out += _html_attachment_findings(att, data, label, ev)

    if ext in ft.MACRO_EXTENSIONS:
        out.append(Finding("ATT_MACRO_EXTENSION", Severity.MEDIUM,
                           f"{label} uses a macro-enabled Office extension (.{ext}).", ev))
    if _has_vba(data, att.detected_type):
        out.append(Finding("ATT_OFFICE_MACRO", Severity.HIGH, f"{label} contains a VBA macro project.", ev))
    if att.detected_type == ft.OOXML_WORD.id and _has_remote_template(data):
        out.append(Finding("ATT_REMOTE_TEMPLATE", Severity.HIGH,
                           f"{label} loads an external template when opened (template injection).", ev))
    if att.detected_type == ft.RTF.id and re.search(rb"\\objdata|\\objupdate|\\objocx", data[:5_000_000]):
        out.append(Finding("ATT_RTF_OBJECT", Severity.HIGH,
                           f"{label} is an RTF with embedded OLE objects (common exploit carrier).", ev))
    return out


def _html_attachment_findings(att: Attachment, data: bytes, label: str, ev: dict) -> list[Finding]:
    out = [Finding("ATT_HTML", Severity.MEDIUM,
                   f"{label} is HTML/SVG; it opens in a browser outside the mail client's protections.", ev)]
    text, _ = decode_text(data, "utf-8")
    html, _ = analyze_html(text, att.part)
    for f in html_findings(html):
        f.evidence.setdefault("filename", att.filename)
        out.append(f)
    att.urls = collect_urls(html.links)
    for url in att.urls:
        out += url_findings(url)

    markers = sorted({m.group(0).strip().lower() for m in _SMUGGLING_RE.finditer(text[:5_000_000])})
    blob = _BASE64_BLOB_RE.search(text[:5_000_000])
    if html.scripts and (blob or len(markers) >= 2):
        out.append(Finding("ATT_HTML_SMUGGLING", Severity.HIGH,
                           f"{label} has script that decodes/assembles data in the browser (HTML smuggling).",
                           {**ev, "markers": markers[:MAX_EXAMPLES], "base64_blob_chars": len(blob.group(0)) if blob else 0}))
    return out


def _has_vba(data: bytes, detected_type: str | None) -> bool:
    if detected_type == ft.OLE.id:
        return "_VBA_PROJECT".encode("utf-16-le") in data or b"_VBA_PROJECT" in data
    if detected_type in (ft.OOXML_WORD.id, ft.OOXML_EXCEL.id, ft.OOXML_PPT.id):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                return any(n.lower().endswith("vbaproject.bin") for n in zf.namelist())
        except Exception:
            return False
    return False


def _has_remote_template(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.lower().endswith(".rels"):
                    info = zf.getinfo(name)
                    if info.file_size < 1_000_000 and _REMOTE_TEMPLATE_RE.search(zf.read(name)):
                        return True
    except Exception:
        return False
    return False


def _type_mismatch_findings(att: Attachment, detected: ft.FileType | None, label: str, ev: dict) -> list[Finding]:
    out = []
    ext = att.extension
    if detected and ext and ext not in detected.extensions:
        ext_type = _category_for_extension(ext)
        both_images = detected.category == "image" and ext_type == "image"
        if not both_images:
            dangerous = detected.category in ("executable", "disk-image", "html")
            out.append(Finding(
                "ATT_TYPE_MISMATCH", Severity.HIGH if dangerous else Severity.MEDIUM,
                f"{label} is named .{ext} but its content is {detected.description}.",
                {**ev, "extension": ext, "detected_type": detected.id},
            ))
    expected = _DECLARED_EXPECT.get(att.content_type)
    if detected and expected is not None and detected.id not in expected:
        mismatch = True
    elif detected and att.content_type.startswith("image/") and detected.category != "image" and detected.id != "svg":
        mismatch = True
    else:
        mismatch = False
    if mismatch:
        out.append(Finding(
            "ATT_DECLARED_TYPE_MISMATCH", Severity.MEDIUM,
            f"{label} is declared as {att.content_type} but its content is {detected.description}.",
            {**ev, "declared": att.content_type, "detected_type": detected.id},
        ))
    return out


def _category_for_extension(ext: str) -> str | None:
    for t in (ft.PNG, ft.JPEG, ft.GIF, ft.BMP, ft.WEBP, ft.TIFF, ft.ICO):
        if ext in t.extensions:
            return "image"
    return None


def _archive_findings(archive: ArchiveInfo, compressed_size: int, label: str, ev: dict) -> list[Finding]:
    out: list[Finding] = []
    ev = {**ev, "format": archive.format}
    if archive.error:
        unsupported = "not supported" in archive.error
        out.append(Finding(
            "ATT_ARCHIVE_UNINSPECTED" if unsupported else "ATT_ARCHIVE_CORRUPT", Severity.LOW,
            f"{label}: archive contents could not be inspected ({archive.error}).", {**ev, "error": archive.error},
        ))
    if is_bomb(archive, compressed_size):
        out.append(Finding("ATT_ZIP_BOMB", Severity.HIGH,
                           f"{label} looks like a decompression bomb "
                           f"({archive.total_uncompressed:,} bytes declared from {compressed_size:,}"
                           f"{', overlapping entries' if archive.overlapping_entries else ''}).",
                           {**ev, "total_uncompressed": archive.total_uncompressed}))
    if archive.encrypted_members:
        out.append(Finding("ATT_ENCRYPTED_ARCHIVE", Severity.MEDIUM,
                           f"{label} contains {archive.encrypted_members} password-protected file(s) that "
                           "scanners cannot inspect; check the body for a password.",
                           {**ev, "encrypted_members": archive.encrypted_members}))
    if archive.max_nesting >= 2:
        out.append(Finding("ATT_ARCHIVE_NESTED", Severity.LOW,
                           f"{label} nests archives {archive.max_nesting} levels deep.", ev))

    traversal, risky = [], []
    for m in archive.members:
        full = f"{m.container}/{m.name}" if m.container else m.name
        norm = m.name.replace("\\", "/")
        if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm) or ".." in norm.split("/"):
            traversal.append(full)
        if m.is_dir:
            continue
        leaf = norm.rsplit("/", 1)[-1]
        ext = ft.extension_of(leaf) or ""
        parts = leaf.lower().split(".")
        double = len(parts) >= 3 and parts[-2] in ft.DOCUMENT_EXTENSIONS and _is_risky_extension(parts[-1])
        detected = next((t for t in (ft.PE, ft.ELF, ft.MACHO, ft.LNK, ft.ISO, ft.VHD, ft.VHDX, ft.ONENOTE, ft.HTML, ft.SVG)
                         if t.id == m.detected_type), None)
        if _is_risky_extension(ext) or double or detected:
            risky.append(full)
    if traversal:
        out.append(Finding("ATT_ARCHIVE_PATH_TRAVERSAL", Severity.MEDIUM,
                           f"{label} has members with absolute or '..' paths.", {**ev, "members": traversal[:MAX_EXAMPLES]}))
    if risky:
        out.append(Finding("ATT_ARCHIVE_RISKY_MEMBER", Severity.HIGH,
                           f"{label} contains {len(risky)} risky file(s): {', '.join(safe_display(r) for r in risky[:3])}"
                           f"{'...' if len(risky) > 3 else ''}.", {**ev, "members": risky[:MAX_EXAMPLES]}))
    if archive.truncated:
        out.append(Finding("ATT_ARCHIVE_TRUNCATED", Severity.LOW,
                           f"{label}: archive analysis stopped at a safety limit; not all contents were inspected.", ev))
    return out


def extract_attachments(tree: MimeTree, attachments: list[Attachment], out_dir: str | Path,
                        source_sha256: str) -> Path:
    """Write attachment payloads to `out_dir` for further analysis in a sandbox.

    Files are stored as ``<sha256>.bin`` so the sender-chosen name and extension can
    never cause execution or path traversal, and are made read-only. A manifest maps
    stored files back to the source email, part and original filename; entries from
    earlier runs into the same directory are kept.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    manifest_path = out / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text())
        if not isinstance(manifest, list):
            manifest = []
    except (OSError, ValueError):
        manifest = []
    seen = {(e.get("source_email_sha256"), e.get("part")) for e in manifest if isinstance(e, dict)}
    payloads = {leaf.info.path: leaf.payload for leaf in tree.leaves}
    for att in attachments:
        data = payloads.get(att.part)
        if data is None:
            continue
        target = out / f"{att.sha256}.bin"
        if not target.exists():
            tmp = out / f".{att.sha256}.tmp"
            tmp.write_bytes(data)
            os.chmod(tmp, 0o444)
            tmp.replace(target)
        att.extracted_to = str(target)
        if (source_sha256, att.part) in seen:
            continue
        manifest.append({
            "source_email_sha256": source_sha256, "stored_as": target.name, "part": att.part, "original_filename": att.filename,
            "content_type": att.content_type, "detected_type": att.detected_type,
            "size": att.size, "md5": att.md5, "sha1": att.sha1, "sha256": att.sha256,
        })
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    return manifest_path
