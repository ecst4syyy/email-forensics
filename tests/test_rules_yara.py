import json
from pathlib import Path

import pytest

from email_forensics.analyzer import AnalysisOptions, analyze_message
from email_forensics.cli import main
from email_forensics.custom_rules import RuleError, evaluate, load_rules
from email_forensics.loader import _info, parse_bytes
import samples as s

ROOT = Path(__file__).resolve().parents[1]
FIX = Path(__file__).parent / "fixtures"
EXAMPLES = ROOT / "examples"


def analyze(raw: bytes, **opts):
    return analyze_message(_info("m", raw, "eml"), raw, parse_bytes(raw), AnalysisOptions(**opts))


def write_rules(tmp_path, rules, name="r.json"):
    path = tmp_path / name
    path.write_text(json.dumps(rules) if name.endswith(".json") else rules)
    return path


BEC = (b"From: CFO <cfo@acme-corp.com>\nReply-To: cfo@acme-c0rp.co\nTo: ap@acme-corp.com\nSubject: Urgent\n"
       b"Date: Tue, 22 Sep 2026 10:00:00 +0000\n\nPlease use our updated bank details for today's payment.\n")


def test_example_rules_load_and_flag():
    rules = load_rules([EXAMPLES / "rules" / "example.toml"])
    assert [r.id for r in rules] == ["PAYMENT_CHANGE_REQUEST", "EXECUTIVE_NAME_FROM_FREEMAIL", "PARTNER_NEWSLETTER"]
    report = analyze(BEC, custom_rules=rules)
    hit = next(f for f in report.findings if f.code == "RULE_PAYMENT_CHANGE_REQUEST")
    assert hit.severity.value == "high" and any("finding HDR_REPLY_TO_MISMATCH" in m for m in hit.evidence["matched"])


def test_any_none_operators_and_fields(tmp_path):
    rules = load_rules([write_rules(tmp_path, [
        {"id": "ANY_ONE", "severity": "low", "any": [{"field": "subject", "equals": "nope"},
                                                       {"field": "header:Reply-To", "contains": "c0rp"}]},
        {"id": "NOT_INTERNAL", "all": [{"field": "subject", "exists": True}],
         "none": [{"field": "from_domain", "in": ["acme-corp.com"]}]},
        {"id": "SCORE_HIGH", "all": [{"field": "score", "gte": 1}, {"finding_prefix": "LOOKALIKE_", "min_severity": "medium"}]},
        {"id": "REGEX_HOST", "all": [{"field": "reply_to_domain", "matches": "c0rp\\.co$"}]},
    ])])
    codes = {f.code for f in analyze(BEC, custom_rules=rules).findings}
    assert {"RULE_ANY_ONE", "RULE_SCORE_HIGH", "RULE_REGEX_HOST"} <= codes
    assert "RULE_NOT_INTERNAL" not in codes


def test_suppression_is_recorded(tmp_path):
    rules = load_rules([write_rules(tmp_path, [{"id": "QUIET", "action": "suppress", "suppress": ["URL_SHORTENER"],
                                                "all": [{"field": "url_host", "equals": "bit.ly"}]}])])
    report = analyze((FIX / "phish_html.eml").read_bytes(), custom_rules=rules)
    assert "URL_SHORTENER" not in {f.code for f in report.findings}
    assert [x.code for x in report.suppressed] == ["URL_SHORTENER"] and report.suppressed[0].rule == "QUIET"


@pytest.mark.parametrize("rules,error", [
    ([{"description": "no id", "all": [{"field": "subject", "exists": True}]}], "needs an id"),
    ([{"id": "X", "all": [{"field": "nonsense", "equals": 1}]}], "unknown field"),
    ([{"id": "X", "all": [{"field": "subject", "equals": "a", "contains": "b"}]}], "exactly one"),
    ([{"id": "X", "all": [{"field": "subject", "matches": "("}]}], "bad regex"),
    ([{"id": "X", "severity": "critical", "all": [{"field": "subject", "exists": True}]}], "unknown severity"),
    ([{"id": "X"}], "no 'all' or 'any'"),
    ([{"id": "X", "action": "suppress", "all": [{"field": "subject", "exists": True}]}], "lists no finding"),
    ([{"id": "X", "all": [{"field": "subject", "exists": True}]}] * 2, "duplicate rule id"),
    ([{"id": "bad id!", "all": [{"field": "subject", "exists": True}]}], "letters, digits"),
])
def test_rule_validation(tmp_path, rules, error):
    with pytest.raises(RuleError, match=error):
        load_rules([write_rules(tmp_path, rules)])


def test_evaluate_without_message_object():
    rules = load_rules([EXAMPLES / "rules" / "example.toml"])
    report = analyze(BEC)
    added, _ = evaluate(rules, report, msg=None)
    assert any(f.code == "RULE_PAYMENT_CHANGE_REQUEST" for f in added)


# --------------------------------------------------------------------------- YARA

yara = pytest.importorskip("yara")


@pytest.fixture
def example_yara():
    from email_forensics.yara_scan import compile_rules
    return compile_rules([EXAMPLES / "yara"])


def test_yara_example_rules(example_yara):
    raw = s.message_with([("Invoice.docm", "application/octet-stream", s.malicious_docm()),
                          ("pay.html", "text/html", s.SMUGGLING_HTML),
                          ("run.ps1", "application/octet-stream", s.PS1_ENCODED)])
    report = analyze(raw, yara_rules=example_yara)
    rules_hit = {m.rule for m in report.yara}
    assert {"HTML_Smuggling_Blob", "PowerShell_EncodedCommand", "Office_AutoExec_Shell"} <= rules_hit
    # The macro text is compressed inside vbaProject.bin; it is matched in the decompressed source.
    vba_hit = next(m for m in report.yara if m.rule == "Office_AutoExec_Shell")
    assert vba_hit.target == "Invoice.docm VBA Module1"
    assert all(f.severity.value == "high" for f in report.findings if f.code == "YARA_MATCH")


def test_yara_scans_archive_members(tmp_path):
    from email_forensics.yara_scan import compile_rules
    rule = tmp_path / "member.yar"
    rule.write_text('rule Inner_Marker { meta: severity = "medium" strings: $m = "INNER-MARKER-42" condition: $m }')
    inner = s.make_zip({"deep/readme.txt": b"xx INNER-MARKER-42 xx"})
    raw = s.message_with([("outer.zip", "application/zip", s.make_zip({"inner.zip": inner}))])
    report = analyze(raw, yara_rules=compile_rules([rule]))
    targets = [m.target for m in report.yara]
    assert any(t.endswith("> inner.zip/deep/readme.txt") for t in targets)
    assert next(f for f in report.findings if f.code == "YARA_MATCH").severity.value == "medium"


def test_yara_cli_and_errors(tmp_path, capsys):
    assert main(["analyze", "--json", "--yara", str(EXAMPLES / "yara"), str(FIX / "phish_html.eml")]) == 0
    data = json.loads(capsys.readouterr().out)
    assert any(m["rule"] == "Credential_Harvest_Form" for m in data["yara"])
    bad = tmp_path / "bad.yar"
    bad.write_text("rule broken { condition: }")
    assert main(["analyze", "--yara", str(bad), str(FIX / "legit.eml")]) == 2
    assert main(["analyze", "--yara", str(tmp_path / "missing.yar"), str(FIX / "legit.eml")]) == 2
    assert main(["analyze", "--rules", str(EXAMPLES / "rules" / "example.toml"), str(FIX / "legit.eml")]) == 0
