import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from email_forensics.analyzer import AnalysisOptions, analyze_bytes, analyze_file
from email_forensics.cli import main
from email_forensics.server import ForensicsServer, _label, is_loopback, parse_multipart
from email_forensics.siem import events, to_cef, to_jsonl
from email_forensics.watch import Watcher
from cfbwriter import build_msg

FIX = Path(__file__).parent / "fixtures"
PHISH = (FIX / "phish_html.eml").read_bytes()
LEGIT = (FIX / "legit.eml").read_bytes()
TOKEN = "s3cret-token-0123456789"


def mbox(*messages: bytes) -> bytes:
    return b"".join(b"From MAILER-DAEMON Thu Jan  1 00:00:00 2026\n" + m.replace(b"\r\n", b"\n") + b"\n"
                    for m in messages)


# --------------------------------------------------------------------------- in-memory analysis


def test_analyze_bytes_matches_file_analysis():
    from_file = analyze_file(FIX / "phish_html.eml")
    (from_bytes,) = analyze_bytes("upload:phish.eml", PHISH)
    assert from_bytes.evidence.sha256 == from_file.evidence.sha256
    assert from_bytes.assessment.score == from_file.assessment.score
    assert from_bytes.evidence.path == "upload:phish.eml"


def test_analyze_bytes_mbox_and_msg():
    reports = analyze_bytes("box", mbox(PHISH, LEGIT))
    assert [r.evidence.path for r in reports] == ["box#1", "box#2"]
    assert reports[0].evidence.container_sha256 == reports[1].evidence.container_sha256
    (msg,) = analyze_bytes("m.msg", build_msg(subject="Outlook", body="hello", sender=("A", "a@x.test")))
    assert msg.evidence.format == "msg" and msg.headers.subject == "Outlook"


# --------------------------------------------------------------------------- SIEM output


def test_jsonl_one_event_per_message():
    reports = analyze_bytes("box", mbox(PHISH, LEGIT))
    lines = to_jsonl(reports).splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["event_type"] == "email_forensics.analysis" and first["verdict"] == "malicious"
    assert first["email"]["from"] == "service@secure-paypa1.com"
    assert any(i["type"] == "domain" and i["value"] == "secure-paypa1.com" for i in first["indicators"])
    assert first["reasons"] and first["score"] >= 70


def test_nested_messages_get_their_own_event_with_parent():
    inner = PHISH
    outer = (b"From: fwd@example.org\r\nTo: soc@example.org\r\nSubject: Fwd: suspicious\r\nMIME-Version: 1.0\r\n"
             b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n'
             b"--b\r\nContent-Type: message/rfc822\r\n\r\n" + inner + b"\r\n--b--\r\n")
    (report,) = analyze_bytes("fwd.eml", outer)
    evs = events(report)
    assert len(evs) == 2 and evs[1]["evidence"]["parent_sha256"] == report.evidence.sha256


def test_cef_escaping_and_severity():
    hostile = PHISH.replace(b"Subject: =?utf-8?b?WW91ciBhY2NvdW50IGlzIGxpbWl0ZWQ=?=", b"Subject: a|b=c\\d")
    (report,) = analyze_bytes("x.eml", hostile)
    line = to_cef([report])
    assert line.startswith("CEF:0|email-forensics|email-forensics|")
    # pipes and backslashes are escaped in the header, so the 8th unescaped '|' starts the extensions
    assert "|MALICIOUS email: a\\|b=c\\\\d|" + str(min(10, round(report.assessment.score / 10))) + "|" in line
    assert "msg=a|b\\=c\\\\d" in line  # '=' escaped in extensions, pipes allowed there
    assert "\n" not in line and "rt=" in line and line.split("rt=")[1].split()[0].isdigit()


# --------------------------------------------------------------------------- REST API


@pytest.fixture
def api():
    servers = []

    def start(token=None, **kw):
        srv = ForensicsServer(("127.0.0.1", 0), AnalysisOptions(), token=token, quiet=True, **kw)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}", srv

    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


def call(url, data=None, headers=None, method=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def multipart(fields: dict[str, str], filename: str, data: bytes) -> tuple[bytes, str]:
    b = "----formboundary7MA4YWxk"
    out = b""
    for k, v in fields.items():
        out += f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    out += (f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: message/rfc822\r\n\r\n").encode() + data + f"\r\n--{b}--\r\n".encode()
    return out, f"multipart/form-data; boundary={b}"


def test_health_and_form(api):
    base, _ = api()
    status, headers, body = call(base + "/api/v1/health")
    assert status == 200 and json.loads(body)["status"] == "ok"
    status, headers, body = call(base + "/")
    assert status == 200 and b'enctype="multipart/form-data"' in body and b"<script" not in body
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert call(base + "/nope")[0] == 404
    assert call(base + "/api/v1/analyze")[0] == 405


def test_analyze_raw_upload_all_formats(api):
    base, srv = api()
    status, headers, body = call(base + "/api/v1/analyze", PHISH, {"Content-Type": "message/rfc822",
                                                                   "X-Filename": "../../etc/phish.eml"})
    assert status == 200 and headers["Content-Type"].startswith("application/json")
    report = json.loads(body)
    assert report["assessment"]["verdict"] == "malicious"
    assert report["evidence"]["path"] == "upload:phish.eml"  # client path components dropped
    for fmt, marker in [("html", b"<!DOCTYPE html>"), ("text", b"VERDICT"), ("jsonl", b'"event_type"'),
                        ("cef", b"CEF:0|"), ("summary", b'"verdict"')]:
        status, _, body = call(base + f"/api/v1/analyze?format={fmt}", PHISH)
        assert status == 200 and marker.lower() in body.lower(), fmt
    status, _, body = call(base + "/api/v1/analyze", mbox(PHISH, LEGIT))
    assert status == 200 and len(json.loads(body)) == 2
    assert srv.analyzed == 8


def test_iocs_endpoint(api):
    base, _ = api()
    status, _, body = call(base + "/api/v1/iocs", PHISH)
    bundle = json.loads(body)
    assert status == 200 and bundle["type"] == "bundle"
    status, _, body = call(base + "/api/v1/iocs?format=misp", PHISH)
    assert status == 200 and json.loads(body)["Event"]["Attribute"]
    status, headers, body = call(base + "/api/v1/iocs?format=csv", PHISH)
    assert status == 200 and headers["Content-Type"].startswith("text/csv") and b"secure-paypa1.com" in body


def test_multipart_upload_with_form_fields(api):
    base, _ = api(token=TOKEN)
    body, ctype = multipart({"format": "summary", "token": TOKEN}, "C:\\Users\\me\\phish.eml", PHISH)
    status, _, out = call(base + "/api/v1/analyze", body, {"Content-Type": ctype})
    assert status == 200
    (row,) = json.loads(out)
    assert row["verdict"] == "malicious" and row["evidence"] == "upload:phish.eml"


def test_parse_multipart_direct():
    body, ctype = multipart({"format": "html"}, "a.eml", b"Subject: x\r\n\r\nhi")
    data, filename, fields = parse_multipart(ctype, body)
    assert data == b"Subject: x\r\n\r\nhi" and filename == "a.eml" and fields == {"format": "html"}


def test_token_required(api):
    base, _ = api(token=TOKEN)
    assert call(base + "/api/v1/health")[0] == 200  # health stays open for load balancers
    status, headers, _ = call(base + "/api/v1/analyze", PHISH)
    assert status == 401 and "Bearer" in headers["WWW-Authenticate"]
    assert call(base + "/api/v1/analyze", PHISH, {"Authorization": "Bearer wrong-token-xxxxxxxx"})[0] == 401
    assert call(base + "/api/v1/analyze", PHISH, {"Authorization": f"Bearer {TOKEN}"})[0] == 200
    status, _, page = call(base + "/")
    assert b'name="token"' in page


def test_errors(api):
    base, _ = api(max_upload=1000)
    assert call(base + "/api/v1/analyze", PHISH)[0] == 413
    assert call(base + "/api/v1/analyze?format=pdf", b"Subject: x\r\n\r\nhi")[0] == 400
    assert call(base + "/api/v1/iocs?format=json", b"Subject: x\r\n\r\nhi")[0] == 400
    assert call(base + "/api/v1/analyze", b"")[0] == 400
    status, _, body = call(base + "/api/v1/analyze", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600)
    assert status == 422 and "error" in json.loads(body)
    body, ctype = multipart({}, "a.eml", b"")
    assert call(base + "/api/v1/analyze", body, {"Content-Type": ctype})[0] == 400


def test_bind_policy():
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("0.0.0.0") and not is_loopback("192.168.1.5")
    with pytest.raises(ValueError, match="without an API token"):
        ForensicsServer(("0.0.0.0", 0))
    with pytest.raises(ValueError, match="at least 16"):
        ForensicsServer(("127.0.0.1", 0), token="short")


def test_label_sanitising():
    assert _label("/tmp/../x y<script>.eml") == "upload:x_y_script_.eml"
    assert _label(None) == "upload:message" and _label("....") == "upload:message"


# --------------------------------------------------------------------------- watch folder


def test_watch_processes_each_file_once(tmp_path):
    inbox, out = tmp_path / "inbox", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.eml").write_bytes(PHISH)
    (inbox / "b.mbox").write_bytes(mbox(LEGIT, PHISH))
    (inbox / "notes.docx").write_bytes(b"ignored")
    (inbox / "broken.msg").write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600)
    seen = []
    w = Watcher(inbox, out, report_format="html", on_report=lambda p, r, e: seen.append((p.name, len(r), e)))
    w.run(once=True)
    assert sorted(n for n, _, _ in seen) == ["a.eml", "b.mbox", "broken.msg"]
    events_lines = (out / "events.jsonl").read_text().splitlines()
    assert len(events_lines) == 3
    assert len(list(out.glob("*.html"))) == 2
    assert json.loads((out / "errors.jsonl").read_text())["path"].endswith("broken.msg")

    # same content under a new name, and a restart, are not re-processed
    (inbox / "copy-of-a.eml").write_bytes(PHISH)
    w2 = Watcher(inbox, out)
    w2.run(once=True)
    assert len((out / "events.jsonl").read_text().splitlines()) == 3
    (inbox / "c.eml").write_bytes(LEGIT.replace(b"Subject:", b"Subject: new"))
    w2.run(once=True)
    assert len((out / "events.jsonl").read_text().splitlines()) == 4
    assert PHISH == (inbox / "a.eml").read_bytes()  # inputs untouched


def test_watch_waits_for_files_to_settle(tmp_path):
    inbox = tmp_path / "in"
    inbox.mkdir()
    w = Watcher(inbox, tmp_path / "out", settle=0.2)
    (inbox / "a.eml").write_bytes(PHISH[:100])
    assert w.poll() == 0  # first sighting
    (inbox / "a.eml").write_bytes(PHISH)  # still being written
    assert w.poll() == 0
    time.sleep(0.25)
    assert w.poll() == 1


def test_watch_rejects_same_dir(tmp_path):
    with pytest.raises(ValueError, match="must not be"):
        Watcher(tmp_path, tmp_path)


# --------------------------------------------------------------------------- CLI


def test_cli_jsonl_and_cef(tmp_path, capsys):
    assert main(["analyze", str(FIX / "phish_html.eml"), "--format", "jsonl"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "malicious"
    out = tmp_path / "events.cef"
    assert main(["analyze", str(FIX / "phish_html.eml"), str(FIX / "legit.eml"), "--format", "cef", "-o", str(out)]) == 0
    assert len(out.read_text().splitlines()) == 2


def test_cli_watch_once(tmp_path, capsys):
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "a.eml").write_bytes(PHISH)
    assert main(["watch", str(inbox), "--output-dir", str(tmp_path / "out"), "--once"]) == 0
    assert "a.eml: malicious" in capsys.readouterr().out
    assert len(list((tmp_path / "out").glob("*.json"))) == 1


def test_cli_serve_refuses_public_bind_without_token(monkeypatch, capsys):
    monkeypatch.delenv("EMAIL_FORENSICS_API_TOKEN", raising=False)
    assert main(["serve", "--host", "0.0.0.0", "--port", "0"]) == 2
    assert "without an API token" in capsys.readouterr().err


def test_multipart_parser_fuzz():
    import random

    from email_forensics.server import HttpError

    body, ctype = multipart({"format": "html", "token": "x"}, 'a "b".eml', PHISH[:300])
    rng = random.Random(7)
    for _ in range(3000):
        b = bytearray(body)
        for _ in range(rng.randint(1, 6)):
            pos = rng.randrange(len(b))
            if rng.random() < 0.5:
                b[pos] = rng.randrange(256)
            else:
                del b[pos:pos + rng.randint(1, 40)]
        try:
            data, filename, fields = parse_multipart(ctype, bytes(b))
        except HttpError:
            continue
        assert data is None or isinstance(data, bytes)
        assert all(isinstance(k, str) and isinstance(v, str) for k, v in fields.items())
