"""Regenerate tests/fixtures/regression/: minimal inputs for crashes found by fuzzing.

Each file once crashed the analyzer (see the comment next to it). The regression
test analyses every file and requires a complete report with no ANALYZER_ERROR.

    python tests/fixtures/build_regression_corpus.py
"""

import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cfbwriter import build_msg  # noqa: E402
from samples import TRANSPORT_HEADERS, malicious_docm, message_with  # noqa: E402

OUT = Path(__file__).with_name("regression")
OUT.mkdir(exist_ok=True)

corpus = {
    # Day 2: charset name with an undecodable byte -> codecs.lookup raised UnicodeEncodeError.
    "encoded_word_surrogate_charset.eml": b"From: a@x.test\nSubject: =?utf\xd3-8?q?hi?= =?base64?b?aGk=?=\n\nbody\n",
    # Day 2: a bytes-to-bytes codec as the body charset.
    "body_charset_base64.eml": b"From: a@x.test\nContent-Type: text/plain; charset=base64\n\nhello\n",
    # Day 2: lone surrogates reaching the text output.
    "invalid_bytes_everywhere.eml": b"From: \xff\xfe@x.test\nSubject: \xd3\xff\nContent-Type: text/html; charset=utf\xd3-8\n\n<a href=\"\xff\">\xfe</a>\n",
    # Day 3: tar.gz declaring a 2 GB member (must stop before decompressing it).
    "tar_huge_member.eml": message_with([("big.tgz", "application/gzip", __import__("gzip").compress(
        (lambda t: (setattr(t, "size", 2 * 1024 ** 3), t.tobuf())[1])(__import__("tarfile").TarInfo("huge.bin"))
        + b"\0" * 4096))]),
    # Day 6: OOXML member with corrupt deflate data -> zlib.error.
    "ooxml_corrupt_deflate.eml": message_with([("x.docm", "application/octet-stream",
                                                (lambda d: d[:d.find(b"word/document.xml") + 60] + b"\xff" * 20
                                                 + d[d.find(b"word/document.xml") + 80:])(malicious_docm()))]),
    # Day 7: transport headers with bare CR/LF line breaks -> HeaderWriteError.
    "msg_header_line_breaks.msg": build_msg(subject="x", body="hi", transport_headers=TRANSPORT_HEADERS.replace(
        "Received: from mail.evil.test", "Received: from mail.evil.te\rt").replace("smtp.mailfrom", "smt\n.mailfrom")),
    # Day 7: non-ASCII transport headers -> UnicodeEncodeError on serialisation.
    "msg_non_ascii_headers.msg": build_msg(subject="x", body="hi", transport_headers=TRANSPORT_HEADERS.replace(
        "Subject: Your account is limited", "Subject: Überweisung 請求書 홨")),
    # Day 7: sender address "x@" -> IndexError inside the stdlib address parser.
    "msg_bad_sender.msg": build_msg(subject="x", body="hi", sender=("Name", "x@"),
                                    recipients=[("R", "@", 1), ("S", "a@", 2)]),
}

# Day 3/6: zip whose "mimetype" member declares a large size (must not be read whole).
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("mimetype", b"application/vnd.oasis.opendocument.text" + b"\0" * 5_000_000)
corpus["odf_huge_mimetype.eml"] = message_with([("doc.odt", "application/octet-stream", buf.getvalue())])

for name, data in corpus.items():
    (OUT / name).write_bytes(data)
print(f"wrote {len(corpus)} files to {OUT}")
