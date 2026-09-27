import gzip
import io
import tarfile

from email_forensics import filetype as ft
from samples import fake_docm, fake_pe, make_zip


def detect_id(data):
    t = ft.detect(data)
    return t.id if t else None


def test_detects_common_types():
    assert detect_id(fake_pe()) == "pe"
    assert detect_id(b"\x7fELF\x02\x01") == "elf"
    assert detect_id(b"%PDF-1.7\n") == "pdf"
    assert detect_id(b"garbage-prefix\n%PDF-1.4") == "pdf"  # header need not be at offset 0
    assert detect_id(b"{\\rtf1\\ansi") == "rtf"
    assert detect_id(b"{\\rt\\objdata") == "rtf"
    assert detect_id(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32) == "ole"
    assert detect_id(b"\x89PNG\r\n\x1a\n") == "png"
    assert detect_id(b"\xff\xd8\xff\xe0") == "jpeg"
    assert detect_id(b"Rar!\x1a\x07\x01\x00") == "rar"
    assert detect_id(b"7z\xbc\xaf\x27\x1c") == "7z"
    assert detect_id(gzip.compress(b"x")) == "gzip"
    assert detect_id(b"\x00" * 0x8001 + b"CD001") == "iso"
    assert detect_id(b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F" + b"\x00" * 10) == "lnk"


def test_detects_zip_subtypes():
    assert detect_id(make_zip({"a.txt": b"x"})) == "zip"
    assert detect_id(fake_docm()) == "docx"
    assert detect_id(make_zip({"META-INF/MANIFEST.MF": b"x"})) == "jar"
    assert detect_id(make_zip({"mimetype": b"application/vnd.oasis.opendocument.text"})) == "odf"


def test_detects_markup():
    assert detect_id(b"<!DOCTYPE html><html>") == "html"
    assert detect_id(b"\xef\xbb\xbf  <html>") == "html"
    assert detect_id("<html><body>".encode("utf-16")) == "html"
    assert detect_id(b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg">') == "svg"
    assert detect_id(b"plain text") is None


def test_tar_detection():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 1
        tf.addfile(info, io.BytesIO(b"x"))
    assert detect_id(buf.getvalue()) == "tar"


def test_extension_of():
    assert ft.extension_of("Invoice.PDF") == "pdf"
    assert ft.extension_of("archive.tar.gz") == "gz"
    assert ft.extension_of("noext") is None
    assert ft.extension_of(None) is None
