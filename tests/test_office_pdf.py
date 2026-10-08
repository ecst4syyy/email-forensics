from email_forensics.office import analyze_ole, analyze_ooxml, analyze_rtf, parse_ole10native
from email_forensics.pdf import analyze_pdf
import samples as s


def test_legacy_doc():
    res = analyze_ole(s.malicious_doc())
    assert res.metadata["author"] == "Jane Attacker" and res.metadata["last_saved_by"] == "builder-pc"
    assert res.metadata["created"].startswith("2026-09-21")
    assert [m.autoexec for m in res.vba] == [["AutoOpen"]]
    [obj] = res.embedded
    assert obj.name == "invoice.exe" and obj.detected_type == "pe"


def test_docm():
    res = analyze_ooxml(s.malicious_docm())
    assert res.metadata["author"] == "Jane Attacker" and res.metadata["company"] == "Evil Ltd"
    assert res.vba and res.vba[0].autoexec == ["AutoOpen"]
    assert res.dde and "DDEAUTO" in res.dde[0]
    assert res.activex == ["word/activeX/activeX1.xml"]
    assert [o.name for o in res.embedded] == ["invoice.exe"]
    types = {e["type"] for e in res.external}
    assert {"oleObject", "hyperlink", "image"} <= types


def test_xlm_and_clean_ooxml():
    res = analyze_ooxml(s.xlm_workbook())
    assert res.xlm_autoexec and any("EXEC" in f for f in res.xlm_macros)
    clean = analyze_ooxml(s.make_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>"}))
    assert not (clean.vba or clean.dde or clean.embedded or clean.external or clean.xlm_macros)
    assert analyze_ooxml(b"not a zip").vba == []


def test_rtf_equation_exploit():
    res = analyze_rtf(s.equation_rtf())
    assert res.rtf_object_classes == ["Equation.3"]
    assert [o.name for o in res.embedded] == ["update.exe"]


def test_ole10native_garbage():
    assert parse_ole10native(b"") is None
    assert parse_ole10native(b"\x00" * 3) is None


def test_pdf_analysis():
    res = analyze_pdf(s.malicious_pdf())
    k = res.keywords
    assert k.get("OpenAction") and k.get("Launch") and k.get("EmbeddedFiles")
    assert k.get("JavaScript", 0) >= 2  # one hidden in the compressed object stream, one #-escaped
    assert "/J#61va#53cript" in res.obfuscated_names
    assert res.uris == ["https://paypa1-secure.test/login"]
    assert "cmd.exe" in res.launch
    assert {"app.launchURL", "this.exportDataObject"} <= set(res.javascript_markers)
    assert [e.detected_type for e in res.embedded] == ["pe"]
    assert res.embedded_names == ["invoice.exe"]  # not the Launch target cmd.exe


def test_clean_pdf():
    res = analyze_pdf(s.clean_pdf())
    assert res.version == "1.4" and not (res.uris or res.javascript or res.embedded or res.launch)
    assert set(res.keywords) == {"Page"}


def test_ooxml_zip_bomb_member_is_not_read():
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("word/embeddings/oleObject1.bin", b"\x00" * (60 * 1024 * 1024))
        zf.writestr("word/vbaProject.bin", b"\x00" * (60 * 1024 * 1024))
    res = analyze_ooxml(buf.getvalue())
    assert res.embedded == [] and res.vba == []


def test_corrupt_deflate_member_is_skipped():
    data = bytearray(s.malicious_docm())
    pos = data.find(b"word/document.xml") + 60
    data[pos:pos + 20] = b"\xff" * 20  # corrupt the compressed bytes of one member
    analyze_ooxml(bytes(data))  # must not raise


import time
import zlib

import pytest


@pytest.mark.parametrize("data", [
    b"%PDF-1.7\n" + b"stream\n" * 300_000,                       # streams without endstream
    b"%PDF-1.7\n/EmbeddedFile " + b"1 0 obj " * 300_000,         # objects without endobj
    b"%PDF-1.7\n/URI (" + b"a" * 3_000_000 + b")",               # giant literal
    b"%PDF-1.7\n" + b"/Launch " * 300_000,                        # keyword spam
    b"%PDF-1.7\n1 0 obj << /Filter /FlateDecode >> stream\n" + zlib.compress(b"\0" * 100_000_000) + b"\nendstream endobj",
], ids=["no-endstream", "no-endobj", "giant-literal", "launch-spam", "deflate-bomb"])
def test_pathological_pdfs_are_bounded(data):
    start = time.time()
    res = analyze_pdf(data)
    assert time.time() - start < 5
    assert res.inflated_bytes <= 50 * 1024 * 1024
