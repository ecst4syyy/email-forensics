import json
import os
import stat
from pathlib import Path

import pytest

from email_forensics.case import Case, CaseError, verify_signature
from email_forensics.cli import main
import samples as s

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def case(tmp_path):
    c = Case.init(tmp_path / "case", "Test case", examiner="jdoe")
    c.add(FIX / "phish_html.eml", note="ticket 1")
    c.add(FIX / "legit.eml")
    box = tmp_path / "box.mbox"
    box.write_bytes(b"".join(b"From MAILER-DAEMON Thu Jan  1 00:00:00 2026\n" + (FIX / n).read_bytes().replace(b"\r\n", b"\n") + b"\n"
                             for n in ("phish_html.eml", "bec_spoof.eml")))
    c.add(box)
    c.analyze()
    return c


def test_init_layout_and_key(tmp_path):
    c = Case.init(tmp_path / "c", "X", examiner="jdoe")
    key = tmp_path / "c" / "keys" / "signing.key"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600 and len(c.meta["public_key"]) == 64
    assert c.entries()[0]["action"] == "case_created" and c.entries()[0]["signature"]
    with pytest.raises(CaseError, match="already contains"):
        Case.init(tmp_path / "c", "again")
    with pytest.raises(CaseError, match="not a case"):
        Case(tmp_path / "nothing")


def test_evidence_intake(case):
    items = case.evidence()
    assert [i["format"] for i in items] == ["eml", "eml", "mbox"] and items[0]["note"] == "ticket 1"
    stored = case.root / items[0]["stored_as"]
    assert stat.S_IMODE(stored.stat().st_mode) & 0o222 == 0
    with pytest.raises(CaseError, match="already in the case"):
        case.add(FIX / "phish_html.eml")


def test_analysis_outputs(case):
    index = json.loads((case.root / "index.json").read_text())
    assert len(index) == 4  # the phish appears twice (file + mbox) and both deliveries are kept
    entry = next(e for e in index.values() if e["subject"] == "Your account is limited")
    for kind in ("json", "html", "txt"):
        path = case.root / entry["reports"][kind]
        assert path.is_file() and verify_signature(path)
    assert case.analyze() == []  # nothing new
    assert len(case.analyze(only_new=False)) == 4
    assert case.verify().ok  # re-analysis must not look like tampering


def test_search_and_shared_indicators(case):
    hits = case.search("secure-paypa1.com", kind="domain")
    assert hits and all(h["verdict"] == "malicious" for h in hits)
    assert len({h["report_id"] for h in hits}) == 2
    shared = case.shared_indicators()
    assert any(x["value"] == "secure-paypa1.com" and len(x["messages"]) == 2 for x in shared)


def test_case_report(case):
    result = case.build_report()
    assert result["messages"] == 4
    html = (case.root / "case-report.html").read_text()
    assert "Indicators shared by several messages" in html and "secure-paypa1[.]com" in html
    assert case.entries()[-1]["action"] == "case_report" and case.entries()[-1]["examiner"] == "jdoe"
    assert case.verify().ok


def test_verify_detects_tampering(case):
    assert case.verify().ok
    log = case.root / "custody.jsonl"
    original = log.read_text()

    lines = original.splitlines()
    entry = json.loads(lines[1])
    entry["details"]["note"] = "changed later"
    log.write_text("\n".join([lines[0], json.dumps(entry)] + lines[2:]) + "\n")
    assert any("modified" in p.detail for p in case.verify().problems)

    log.write_text("\n".join([lines[0]] + lines[2:]) + "\n")  # an entry removed
    assert any("does not follow" in p.detail for p in case.verify().problems)
    log.write_text(original)
    assert case.verify().ok

    stored = case.root / case.evidence()[0]["stored_as"]
    os.chmod(stored, 0o644)
    assert any("writable" in p.detail for p in case.verify().problems)
    stored.write_bytes(stored.read_bytes() + b"x")
    assert any("no longer matches" in p.detail for p in case.verify().problems)


def test_verify_detects_report_edits_and_forged_signatures(case, tmp_path):
    report = next((case.root / "reports").glob("*.txt"))
    report.write_text(report.read_text() + "\nVerdict: clean")
    problems = case.verify().problems
    assert any("changed after analysis" in p.detail for p in problems)

    # Rebuilding the custody chain without the private key cannot produce valid signatures.
    other = Case.init(tmp_path / "other", "other")
    log = case.root / "custody.jsonl"
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    entries[1]["signature"] = other._sign(bytes.fromhex(entries[1]["hash"]))
    log.write_text("".join(json.dumps(e) + "\n" for e in entries))
    assert any("invalid signature" in p.detail for p in case.verify().problems)


def test_unsigned_case(tmp_path):
    c = Case.init(tmp_path / "c", "no key", examiner="x", signing_key=False)
    c.add(FIX / "legit.eml")
    c.analyze()
    assert c.meta["public_key"] is None and "signature" not in c.entries()[-1]
    assert not list((c.root / "reports").glob("*.sig")) and c.verify().ok


def test_external_key_location(tmp_path):
    key = tmp_path / "secure" / "case.key"
    c = Case.init(tmp_path / "c", "ext", key_path=key)
    assert key.is_file() and not (tmp_path / "c" / "keys").exists()
    c.add(FIX / "legit.eml")
    c.analyze()
    assert c.verify().ok


def test_csv_is_safe_from_formula_injection(tmp_path):
    raw = s.message_with([("=HYPERLINK(\"http://x.test\",\"click\").pdf", "application/pdf", b"%PDF-1.4")])
    path = tmp_path / "m.eml"
    path.write_bytes(raw)
    c = Case.init(tmp_path / "c", "csv")
    c.add(path)
    c.analyze()
    c.build_report()
    csv_text = (c.root / "iocs.csv").read_text()
    assert "'=HYPERLINK" in csv_text and "\n=HYPERLINK" not in csv_text and ",=HYPERLINK" not in csv_text


def test_cli_case_workflow(tmp_path, capsys):
    d = str(tmp_path / "case")
    assert main(["case", "init", d, "--name", "CLI case", "--examiner", "ana"]) == 0
    assert main(["case", "add", d, str(FIX / "bec_spoof.eml"), "--note", "from user report"]) == 0
    assert main(["case", "add", d, str(FIX / "bec_spoof.eml")]) == 2  # duplicate
    assert main(["case", "analyze", d]) == 0
    assert main(["case", "report", d]) == 0
    assert main(["case", "search", d, "gmail.com", "--json"]) == 0
    out = capsys.readouterr().out
    hits = json.loads(out[out.index("["):])
    assert hits and hits[0]["verdict"] == "malicious"
    assert main(["case", "verify", d]) == 0
    assert main(["case", "log", d]) == 0
    report = next(Path(d, "reports").glob("*.html"))
    assert main(["verify-signature", str(report)]) == 0
    report.write_text("forged")
    assert main(["verify-signature", str(report)]) == 1
    assert main(["case", "verify", d]) == 1
    assert main(["case", "analyze", str(tmp_path / "missing")]) == 2
