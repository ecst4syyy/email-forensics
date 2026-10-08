import email.policy
import hashlib
import json
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

import pytest

from cfbwriter import build_msg
from email_forensics.analyzer import AnalysisOptions, analyze_file, analyze_message, analyze_path
from email_forensics.cli import main
from email_forensics.loader import EvidenceError, _info, detect_format, iter_mbox, load_evidence, parse_bytes
from email_forensics.msg import decompress_rtf, msg_to_message
from email_forensics.resolver import RecordingResolver, ReplayResolver
import samples as s

FIX = Path(__file__).parent / "fixtures"


def codes(report):
    return {f.code for f in report.findings}


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return path


# --------------------------------------------------------------------------- .msg

def test_msg_with_transport_headers(tmp_path):
    report = analyze_file(write(tmp_path, "phish.msg", s.phish_msg()))
    e, h = report.evidence, report.headers
    assert e.format == "msg" and e.converted and e.sha256 == hashlib.sha256(s.phish_msg()).hexdigest()
    assert h.subject == "Your account is limited" and h.reply_to == ["billing@paypa1-support.test"]
    assert h.hops[0].from_ip == "81.2.69.160"
    assert [r.method for r in h.auth_results] == ["spf", "dmarc"]
    assert report.msg.has_transport_headers and report.msg.submit_time.startswith("2026-09-22")
    assert {"AUTH_SPF_FAIL", "AUTH_DMARC_FAIL", "URL_TEXT_MISMATCH", "ATT_DOUBLE_EXTENSION", "ATT_EXECUTABLE",
            "LOOKALIKE_COMBO", "MSG_SOURCE"} <= codes(report)
    assert [a.filename for a in report.attachments] == ["Invoice.pdf.exe"]


def test_msg_drops_original_content_type():
    msg, info = msg_to_message(s.phish_msg())
    assert 'boundary="orig"' not in str(msg["Content-Type"])
    assert msg.get_content_type() == "multipart/mixed"


def test_msg_without_transport_headers_and_embedded_message(tmp_path):
    report = analyze_file(write(tmp_path, "sent.msg", s.sent_item_msg()))
    h = report.headers
    assert h.from_address == "bob@corp.test" and h.to == ["soc@corp.test"] and h.cc == ["alice@corp.test"]
    assert h.date is not None and not report.msg.has_transport_headers
    [nested] = report.nested
    assert nested.filename == "Original phish.msg"
    assert nested.report.headers.subject == "Your account is limited"
    assert "AUTH_DMARC_FAIL" in codes(nested.report)
    assert "NESTED_MESSAGE_SUSPICIOUS" in codes(report)


def test_msg_rtf_only_body(tmp_path):
    rtf = b"{\\rtf1\\ansi Pay invoice at http://203.0.113.9/pay\\par}"
    stored = (len(rtf) + 12).to_bytes(4, "little") + len(rtf).to_bytes(4, "little") + b"MELA" + b"\x00" * 4 + rtf
    assert decompress_rtf(stored) == rtf
    report = analyze_file(write(tmp_path, "rtf.msg", build_msg(subject="rtf", rtf=stored, sender=("A", "a@x.test"))))
    assert [a.filename for a in report.attachments] == ["body.rtf"]
    assert "http://203.0.113.9/pay" in report.body.text_bodies[0].preview


def test_msg_dkim_is_not_reported_as_tampering(tmp_path):
    signed = (FIX / "dkim" / "rsa_relaxed.eml").read_bytes().decode()
    head, _, body = signed.partition("\r\n\r\n")
    raw = build_msg(subject="Quarterly   numbers", transport_headers=head + "\r\n", body=body,
                    sender=("Alice", "alice@signer.test"))
    report = analyze_file(write(tmp_path, "signed.msg", raw))
    assert "AUTHV_DKIM_BODY_MODIFIED" not in codes(report)
    assert "AUTHV_DKIM_UNVERIFIABLE" in codes(report)


def test_ole_file_that_is_not_msg(tmp_path):
    with pytest.raises(EvidenceError, match="not an Outlook message"):
        load_evidence(write(tmp_path, "x.doc", s.malicious_doc()))


# --------------------------------------------------------------------------- mbox

def make_mbox(*messages: bytes) -> bytes:
    out = b""
    for m in messages:
        m = m.replace(b"\r\n", b"\n")
        m = b"\n".join(b">" + line if line.startswith(b"From ") else line for line in m.split(b"\n"))
        out += b"From MAILER-DAEMON Thu Jan  1 00:00:00 2026\n" + m.rstrip(b"\n") + b"\n\n"
    return out


def test_mbox_iteration(tmp_path):
    msgs = [(FIX / n).read_bytes() for n in ("legit.eml", "bec_spoof.eml", "phish_html.eml")]
    body_with_from = b"From: a@x.test\nSubject: quoting\n\nFrom here on the line starts with From\n"
    path = write(tmp_path, "box.mbox", make_mbox(*msgs, body_with_from))
    assert detect_format(path) == "mbox"
    items = list(iter_mbox(path))
    assert [i[0].path.rsplit("#", 1)[1] for i in items] == ["1", "2", "3", "4"]
    file_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    assert all(i[0].container_sha256 == file_sha and i[0].format == "mbox" for i in items)
    assert items[3][1].endswith(b"From here on the line starts with From\n")  # >From unquoted
    reports = list(analyze_path(path))
    assert [r.headers.subject for r in reports] == ["Quarterly report", "Urgent wire transfer",
                                                   "Your account is limited", "quoting"]
    assert "HDR_DISPLAY_NAME_SPOOF" in codes(reports[1])


def test_cli_summary(tmp_path, capsys):
    box = write(tmp_path, "box.mbox", make_mbox((FIX / "legit.eml").read_bytes(), (FIX / "bec_spoof.eml").read_bytes()))
    msg = write(tmp_path, "p.msg", s.phish_msg())
    assert main(["analyze", "--summary", str(box), str(msg)]) == 0
    out = capsys.readouterr().out
    assert "Quarterly report" in out and "Urgent wire transfer" in out and "3 message(s): 2 malicious, 1 clean" in out
    assert main(["analyze", "--summary", "--json", str(box)]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[1]["high"] >= 1 and rows[0]["high"] == 0


def test_detect_format(tmp_path):
    assert detect_format(FIX / "legit.eml") == "eml"
    assert detect_format(write(tmp_path, "x.msg", s.phish_msg())) == "msg"
    assert detect_format(write(tmp_path, "notes.txt", b"From the desk of\nhello")) == "eml"


# --------------------------------------------------------------------------- nested messages

def test_forwarded_phish_gets_its_own_report(tmp_path):
    report = analyze_file(write(tmp_path, "fwd.eml", s.forwarded_eml()))
    assert report.body.urls == []  # the inner message's links are not mixed into the outer body
    [nested] = report.nested
    inner = nested.report
    assert inner.headers.subject == "Password expires today" and inner.evidence.format == "attached"
    assert {"URL_IP_HOST", "URL_TEXT_MISMATCH"} <= codes(inner)
    suspicious = [f for f in report.findings if f.code == "NESTED_MESSAGE_SUSPICIOUS"]
    assert suspicious and suspicious[0].severity.value == "high"
    data = json.loads(json.dumps(report.to_dict()))
    assert data["nested"][0]["report"]["headers"]["subject"] == "Password expires today"


def test_signed_message_attached_still_verifies():
    inner = (FIX / "dkim" / "rsa_relaxed.eml").read_bytes()
    outer = EmailMessage(policy=email.policy.default)
    outer["From"], outer["Subject"] = "a@x.test", "fwd"
    outer.set_content("see attached")
    outer.add_attachment(BytesParser(policy=email.policy.default).parsebytes(inner))
    raw = outer.as_bytes()
    opts = AnalysisOptions(resolver=RecordingResolver(ReplayResolver(FIX / "dkim" / "dns.json")))
    report = analyze_message(_info("outer", raw, "eml"), raw, parse_bytes(raw), opts)
    assert report.nested[0].report.auth.dkim[0].result == "pass"


def test_nesting_depth_is_limited():
    msg = parse_bytes(b"From: a@x.test\nSubject: level 0\n\nbottom\n")
    for level in range(1, 7):
        outer = EmailMessage(policy=email.policy.default)
        outer["From"], outer["Subject"] = "a@x.test", f"level {level}"
        outer.set_content("wrapper")
        outer.add_attachment(msg)
        msg = outer
    raw = msg.as_bytes()
    report = analyze_message(_info("deep", raw, "eml"), raw, parse_bytes(raw), AnalysisOptions())
    depth = 0
    while report.nested:
        report = report.nested[0].report
        depth += 1
    assert depth == 3


def test_eml_attachment_file_is_analysed(tmp_path):
    raw = s.message_with([("reported.eml", "application/octet-stream", (FIX / "bec_spoof.eml").read_bytes())])
    report = analyze_file(write(tmp_path, "m.eml", raw))
    assert report.nested and "HDR_DISPLAY_NAME_SPOOF" in codes(report.nested[0].report)


def test_msg_with_non_ascii_transport_headers(tmp_path):
    headers = s.TRANSPORT_HEADERS.replace("Subject: Your account is limited", "Subject: Überweisung fällig 請求書")
    report = analyze_file(write(tmp_path, "intl.msg", build_msg(subject="x", transport_headers=headers, body="hi")))
    assert "Überweisung" in report.headers.subject or "berweisung" in report.headers.subject


def test_msg_without_transport_headers_keeps_non_ascii_text():
    """Rebuilt headers must carry Unicode subjects and names as proper encoded-words, not as
    raw 8-bit text (which re-serialises as =?unknown-8bit?...?= and looks malformed)."""
    from email_forensics.analyzer import analyze_bytes

    subject = "Gaurav, your Fitness Nation Bedford account – payment due · Müller €"
    data = build_msg(subject=subject, body="Payment due", sender=("Fitness Nation – Bedford", "noreply@fitnessnation.example"),
                     recipients=[("Jürgen Groß", "jg@example.de", 1)])
    (report,) = analyze_bytes("x.msg", data)
    h = report.headers
    assert h.subject == subject
    assert h.from_display_name == "Fitness Nation – Bedford" and h.from_address == "noreply@fitnessnation.example"
    assert h.to == ["jg@example.de"]
    assert "HDR_ENCODED_WORD_ERROR" not in {f.code for f in report.findings}
