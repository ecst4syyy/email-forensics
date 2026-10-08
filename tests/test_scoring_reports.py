import csv
import io
import json
import re
from pathlib import Path

import pytest

from email_forensics.analyzer import analyze_file
from email_forensics.cli import main
from email_forensics.iocs import extract_iocs, to_csv, to_misp, to_stix
from email_forensics.models import Finding, Severity
from email_forensics.report_html import defang, esc, render_html
from email_forensics.scoring import assess, category_of, verdict_for
import samples as s

FIX = Path(__file__).parent / "fixtures"


def report_for(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return analyze_file(path)


# --------------------------------------------------------------------------- scoring

@pytest.mark.parametrize("name,verdict", [
    ("legit.eml", "clean"), ("bec_spoof.eml", "malicious"), ("phish_html.eml", "malicious"),
    ("malicious_attachments.eml", "malicious"),
])
def test_fixture_verdicts(name, verdict):
    assert analyze_file(FIX / name).assessment.verdict == verdict


def test_score_is_explained_and_bounded():
    a = analyze_file(FIX / "phish_html.eml").assessment
    assert 0 <= a.score <= 100 and a.reasons
    assert a.reasons == sorted(a.reasons, key=lambda r: -r.points)
    assert all(r.points > 0 for r in a.reasons)


def test_diminishing_returns_within_a_category():
    rep = analyze_file(FIX / "legit.eml")
    rep.findings = [Finding("URL_SHORTENER", Severity.HIGH, "x") for _ in range(10)]
    many_same = assess(rep).score
    rep.findings = [Finding(c, Severity.HIGH, "x") for c in ("URL_SHORTENER", "ATT_EXECUTABLE", "AUTH_SPF_FAIL")]
    spread = assess(rep).score
    assert many_same < spread  # ten link findings < three findings in three different areas


def test_conclusive_findings_set_a_floor():
    rep = analyze_file(FIX / "legit.eml")
    rep.findings = [Finding("LNK_RUNS_COMMAND", Severity.HIGH, "shortcut runs powershell")]
    a = assess(rep)
    assert a.score >= 90 and a.verdict == "malicious" and a.floor == "LNK_RUNS_COMMAND"


def test_info_findings_do_not_score():
    rep = analyze_file(FIX / "legit.eml")
    rep.findings = [Finding("RCV_ORIGIN_IP", Severity.INFO, "x"), Finding("DOC_METADATA", Severity.INFO, "y")]
    assert assess(rep).score == 0


def test_nested_score_propagates(tmp_path):
    rep = report_for(tmp_path, "fwd.eml", s.forwarded_eml())
    inner = rep.nested[0].report.assessment
    assert rep.assessment.score >= inner.score
    assert any(r.code == "NESTED_MESSAGE_SUSPICIOUS" for r in rep.assessment.reasons)


def test_categories_and_thresholds():
    assert category_of(Finding("LOOKALIKE_TYPO", Severity.HIGH, "", {"location": "URL"})) == "links and content"
    assert category_of(Finding("LOOKALIKE_TYPO", Severity.HIGH, "", {"location": "From"})) == "sender identity"
    assert category_of(Finding("AUTHV_DKIM_FAIL", Severity.HIGH, "")) == "authentication"
    assert [verdict_for(x) for x in (0, 11, 12, 34, 35, 69, 70, 100)] == \
        ["clean", "clean", "caution", "caution", "suspicious", "suspicious", "malicious", "malicious"]


# --------------------------------------------------------------------------- HTML

def test_html_is_inert_even_for_hostile_content(tmp_path):
    hostile = (b'From: "<script>alert(1)</script>" <x@evil.test>\nSubject: <img src=x onerror=alert(1)>\n'
               b"Content-Type: text/html\n\n<a href=\"javascript:alert(1)\">http://evil.test/</a>"
               b"<iframe src=https://evil.test></iframe><style>body{background:url(https://t.test/p)}</style>\n")
    page = render_html([report_for(tmp_path, "h.eml", hostile)])
    assert "<script>" not in page and "<img" not in page and "<iframe" not in page
    tags = re.findall(r"<[a-zA-Z][^>]*>", page)  # only real tags; escaped text cannot contain "<"
    assert not [t for t in tags if re.search(r"(?i)\s(?:href|src|on\w+|style)\s*=", t) or t.lower().startswith("<a ")]
    assert "&lt;img src=x onerror=alert(1)&gt;" in page  # shown as text
    assert not re.search(r"(?i)https?://", page)  # every URL is defanged
    assert "default-src 'none'" in page
    assert "hxxps://evil[.]test" in page  # the iframe source, defanged


def test_html_multiple_reports_and_nested(tmp_path):
    reports = [analyze_file(FIX / "legit.eml"), report_for(tmp_path, "fwd.eml", s.forwarded_eml())]
    page = render_html(reports)
    assert page.count('<article id="msg') == 2 and "Attached message" in page and "<h2>Messages</h2>" in page


def test_defang_and_escape():
    assert defang("https://www.example.com/a.b?c=d.e") == "hxxps://www[.]example[.]com/a.b?c=d.e"
    assert defang("ftp://u@host.test/x") == "fxp://u[@]host[.]test/x"
    assert defang("203.0.113.9") == "203[.]0[.]113[.]9"
    assert esc('<b>"x"</b> see http://a.test') == "&lt;b&gt;&quot;x&quot;&lt;/b&gt; see hxxp://a.test"
    assert esc("‮reversed") == "\\u202ereversed"


# --------------------------------------------------------------------------- IOCs

def test_ioc_extraction(tmp_path):
    rep = report_for(tmp_path, "day6.eml", s.message_with([
        ("Invoice.docm", "application/octet-stream", s.malicious_docm()),
        ("Statement.pdf", "application/pdf", s.malicious_pdf())]))
    iocs = extract_iocs(rep)
    kinds = {(i.type, i.role) for i in iocs}
    assert ("email-addr", "from") in kinds and ("sha256", "attachment") in kinds
    assert ("sha256", "embedded-file") in kinds  # invoice.exe inside the docm/pdf
    assert ("url", "attachment-link") in kinds
    assert {i.verdict for i in iocs} == {"malicious"}
    values = {i.value for i in iocs}
    assert "https://paypa1-secure.test/login" in values and "invoice.exe" in values


def test_ioc_formats(tmp_path):
    rep = analyze_file(FIX / "phish_html.eml")
    iocs = extract_iocs(rep)
    rows = list(csv.DictReader(io.StringIO(to_csv(iocs))))
    assert rows and set(rows[0]) == {"type", "value", "role", "evidence_sha256", "verdict", "context"}

    bundle = json.loads(to_stix(iocs, [rep]))
    assert bundle["type"] == "bundle"
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert indicators and all(o["pattern"].startswith("[") and o["spec_version"] == "2.1" for o in indicators)
    assert any("url:value = 'https://bit.ly/3xYz9'" in o["pattern"] for o in indicators)
    report_obj = next(o for o in bundle["objects"] if o["type"] == "report")
    assert set(report_obj["object_refs"]) == {o["id"] for o in indicators}
    # Deterministic ids: the same evidence gives the same indicator ids.
    again = json.loads(to_stix(extract_iocs(analyze_file(FIX / "phish_html.eml")), [rep]))
    assert sorted(o["id"] for o in again["objects"]) == sorted(o["id"] for o in bundle["objects"])

    event = json.loads(to_misp(iocs, [rep]))["Event"]
    types = {a["type"] for a in event["Attribute"]}
    assert {"email-src", "url", "domain", "ip-src", "email-subject"} <= types
    assert event["threat_level_id"] == "1"


def test_stix_escaping():
    from email_forensics.iocs import Indicator
    ind = Indicator("url", "http://x.test/a'b\\c", "link", "0" * 64, "malicious")
    rep = analyze_file(FIX / "legit.eml")
    pattern = next(o["pattern"] for o in json.loads(to_stix([ind], [rep]))["objects"] if o["type"] == "indicator")
    assert pattern == "[url:value = 'http://x.test/a\\'b\\\\c']"


# --------------------------------------------------------------------------- CLI

def test_cli_outputs(tmp_path, capsys):
    html_out, ioc_csv, ioc_misp = tmp_path / "r.html", tmp_path / "i.csv", tmp_path / "i.json"
    assert main(["analyze", str(FIX / "phish_html.eml"), "--format", "html", "-o", str(html_out),
                 "--iocs", str(ioc_csv)]) == 0
    assert html_out.read_text().startswith("<!doctype html>")
    assert ioc_csv.read_text().startswith("type,value,role")
    assert main(["analyze", str(FIX / "phish_html.eml"), "-o", str(tmp_path / "x.txt"),
                 "--iocs", str(ioc_misp), "--ioc-format", "misp"]) == 0
    assert "Event" in json.loads(ioc_misp.read_text())
    capsys.readouterr()


def test_cli_fail_on(capsys):
    assert main(["analyze", str(FIX / "legit.eml"), "--fail-on", "suspicious"]) == 0
    assert main(["analyze", str(FIX / "phish_html.eml"), "--fail-on", "malicious"]) == 1
    assert main(["analyze", str(FIX / "legit.eml"), str(FIX / "bec_spoof.eml"), "--fail-on", "caution"]) == 1
    out = capsys.readouterr().out
    assert "=== Verdict: MALICIOUS" in out
