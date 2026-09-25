from email_forensics.analyzer import analyze_file
from email_forensics.headers import analyze_headers
from email_forensics.loader import parse_bytes
from email_forensics.domains import org_domain
from email_forensics.rules import run_header_rules


def codes(findings):
    return {f.code for f in findings}


def run(raw: bytes):
    msg = parse_bytes(raw)
    return codes(run_header_rules(msg, analyze_headers(msg)))


def test_legit_message_has_no_warnings(fixture_path):
    report = analyze_file(fixture_path("legit.eml"))
    assert {f.code for f in report.findings if f.severity.value != "info"} == set()
    assert "RCV_ORIGIN_IP" in codes(report.findings)


def test_bec_spoof_is_flagged(fixture_path):
    found = codes(analyze_file(fixture_path("bec_spoof.eml")).findings)
    assert {
        "HDR_DISPLAY_NAME_SPOOF",
        "HDR_REPLY_TO_MISMATCH",
        "HDR_RETURN_PATH_MISMATCH",
        "HDR_DUPLICATE",
        "AUTH_SPF_FAIL",
        "AUTH_DMARC_FAIL",
        "RCV_TIME_REVERSAL",
        "HDR_DATE_AFTER_DELIVERY",
    } <= found


def test_findings_sorted_by_severity(fixture_path):
    ranks = [f.severity.rank for f in analyze_file(fixture_path("bec_spoof.eml")).findings]
    assert ranks == sorted(ranks, reverse=True)


def test_malformed_message_does_not_crash(fixture_path):
    found = codes(analyze_file(fixture_path("malformed.eml")).findings)
    assert {"HDR_BAD_DATE", "HDR_MISSING_MESSAGE_ID", "RCV_BAD_TIMESTAMP"} <= found


def test_same_org_subdomain_is_not_mismatch():
    found = run(b"From: a@example.co.uk\nReply-To: b@mail.example.co.uk\n\nx\n")
    assert "HDR_REPLY_TO_MISMATCH" not in found


def test_display_name_with_same_domain_is_fine():
    found = run(b'From: "alice@example.com" <alice@example.com>\n\nx\n')
    assert "HDR_DISPLAY_NAME_SPOOF" not in found


def test_dkim_pass_for_unrelated_domain_is_not_aligned():
    found = run(
        b"From: a@bank.com\n"
        b"Authentication-Results: mx.local; dkim=pass header.d=sendgrid.net\n\nx\n"
    )
    assert "AUTH_DKIM_NOT_ALIGNED" in found


def test_org_domain():
    assert org_domain("mail.example.com") == "example.com"
    assert org_domain("a.b.example.co.uk") == "example.co.uk"
    assert org_domain(None) is None
