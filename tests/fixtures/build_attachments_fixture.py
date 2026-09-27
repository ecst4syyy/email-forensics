"""Regenerate tests/fixtures/malicious_attachments.eml (inert samples only).

Run from the repository root:  python tests/fixtures/build_attachments_fixture.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from samples import SMUGGLING_HTML, fake_docm, fake_pe, make_zip, message_with  # noqa: E402

nested = make_zip({"payload/Invoice.pdf.exe": fake_pe(), "readme.txt": b"open the invoice"})
raw = message_with([
    ("Invoice_2026.zip", "application/zip", make_zip({"docs.zip": nested, "secret.js": b"inert"}, {"secret.js"})),
    ("Remittance.html", "text/html", SMUGGLING_HTML),
    ("Q3-report.docm", "application/vnd.ms-word.document.macroEnabled.12", fake_docm()),
    ("photo_‮gpj.scr", "image/jpeg", fake_pe()),
    ("statement.pdf", "application/pdf", b"%PDF-1.7\n1 0 obj<<>>endobj\n%%EOF\n"),
], body="Password for the archive: 1234")
out = Path(__file__).with_name("malicious_attachments.eml")
out.write_bytes(raw)
print(f"wrote {out} ({len(raw)} bytes)")
