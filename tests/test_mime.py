from email_forensics.loader import parse_bytes
from email_forensics.mime import MAX_DEPTH, decode_text, walk_mime


def test_mime_paths_and_attachments():
    raw = (
        b'Content-Type: multipart/mixed; boundary="M"\n\n'
        b'--M\nContent-Type: multipart/alternative; boundary="A"\n\n'
        b'--A\nContent-Type: text/plain\n\nhi\n--A\nContent-Type: text/html\n\n<p>hi</p>\n--A--\n'
        b'--M\nContent-Type: application/pdf; name="x.pdf"\nContent-Disposition: attachment; filename="x.pdf"\n'
        b'Content-Transfer-Encoding: base64\n\nJVBERi0=\n--M--\n'
    )
    tree = walk_mime(parse_bytes(raw))
    assert [(p.path, p.content_type) for p in tree.parts] == [
        ("1", "multipart/mixed"),
        ("1.1", "multipart/alternative"),
        ("1.1.1", "text/plain"),
        ("1.1.2", "text/html"),
        ("1.2", "application/pdf"),
    ]
    pdf = tree.parts[-1]
    assert pdf.is_attachment and pdf.filename == "x.pdf"
    assert pdf.size == 5 and len(pdf.sha256) == 64
    assert [leaf.info.path for leaf in tree.leaves] == ["1.1.1", "1.1.2", "1.2"]


def test_mime_depth_limit():
    raw = b""
    for i in range(MAX_DEPTH + 5):
        raw += f'Content-Type: multipart/mixed; boundary="b{i}"\n\n--b{i}\n'.encode()
    raw += b"Content-Type: text/plain\n\nx\n"
    tree = walk_mime(parse_bytes(raw))
    assert "MIME_TOO_DEEP" in {f.code for f in tree.findings}


def test_unknown_transfer_encoding():
    tree = walk_mime(parse_bytes(b"Content-Transfer-Encoding: x-weird\n\nbody\n"))
    assert "MIME_UNKNOWN_TRANSFER_ENCODING" in {f.code for f in tree.findings}


def test_decode_text_handles_bad_charsets():
    assert decode_text(b"caf\xc3\xa9", "utf-8") == ("café", None)
    text, problem = decode_text(b"abc", "no-such-charset")
    assert text == "abc" and "unknown charset" in problem
    text, problem = decode_text(b"\xff\xfe", "utf-8")
    assert "invalid bytes" in problem


def test_decode_text_rejects_hostile_charset_names():
    # Found by fuzzing: surrogate escapes in the name, and bytes-to-bytes codecs.
    assert "unknown charset" in decode_text(b"abc", "utf\udcd3-8")[1]
    assert "unknown charset" in decode_text(b"abc", "base64")[1]
