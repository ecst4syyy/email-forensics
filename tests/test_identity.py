from email_forensics.analyzer import analyze_file
from email_forensics.body import analyze_body
from email_forensics.headers import analyze_headers
from email_forensics.identity import analyze_identity, parse_forefront
from email_forensics.loader import parse_bytes
from email_forensics.mailer import fingerprint


def identity(raw: bytes, protected=()):
    msg = parse_bytes(raw)
    h = analyze_headers(msg)
    body, _ = analyze_body(msg)
    ident, findings = analyze_identity(msg, h, body, [], protected)
    return ident, {f.code: f for f in findings}


def msg(headers: str, body: str = "hi") -> bytes:
    return (headers.strip() + "\n\n" + body + "\n").encode()


def test_display_name_brand_on_freemail_is_high():
    _, found = identity(msg("From: Microsoft Support <ms.help@outlook.com>\nTo: a@victim.test"))
    assert found["HDR_DISPLAY_NAME_BRAND"].severity.value == "high"


def test_display_name_brand_other_domain_is_medium():
    _, found = identity(msg("From: PayPal Service <service@notify-center.net>\nTo: a@victim.test"))
    assert found["HDR_DISPLAY_NAME_BRAND"].severity.value == "medium"


def test_display_name_brand_legitimate_domains():
    for header in ("From: PayPal <service@paypal.com>", "From: Amazon.de <versand@amazon.de>",
                   "From: Chase Miller <chase@example.com>",  # a first name, not the bank
                   "From: Weekly Market Outlook <news@example.com>",
                   "From: ups and downs <x@example.com>"):
        _, found = identity(msg(header + "\nTo: a@victim.test"))
        assert "HDR_DISPLAY_NAME_BRAND" not in found, header


def test_display_name_uses_recipient_org():
    _, found = identity(msg("From: ACME-Corp IT Desk <it.desk@gmail.com>\nTo: bob@acme-corp.com"))
    assert found["HDR_DISPLAY_NAME_ORG"].severity.value == "high"
    _, found = identity(msg("From: ACME-Corp IT Desk <it@acme-corp.com>\nTo: bob@acme-corp.com"))
    assert "HDR_DISPLAY_NAME_ORG" not in found


def test_recipient_domain_lookalike_sender():
    ident, found = identity(msg("From: CFO <cfo@acme-c0rp.com>\nTo: ap@acme-corp.com"))
    assert "LOOKALIKE_HOMOGLYPH" in found
    assert ident.recipient_domains == ["acme-corp.com"]


def test_configured_protected_domain_and_delivered_to():
    _, found = identity(msg("From: a@supp1ier-co.com\nTo: undisclosed-recipients:;"), protected=["supplier-co.com"])
    assert "LOOKALIKE_HOMOGLYPH" in found
    ident, _ = identity(msg("From: a@x.test\nDelivered-To: me@acme-corp.com"))
    assert ident.recipient_domains == ["acme-corp.com"]


def test_reply_to_lookalike():
    _, found = identity(msg("From: a@acme-corp.com\nReply-To: a@acme-corp.co\nTo: b@acme-corp.com"))
    assert found["LOOKALIKE_TLD_SWAP"].evidence["location"] == "Reply-To"


def test_url_lookalikes_use_body_urls():
    raw = msg("From: a@x.test\nTo: b@y.test\nContent-Type: text/html",
              '<a href="https://login.microsoftonline.com.auth-check.net/">Sign in</a>')
    ident, found = identity(raw)
    assert found["LOOKALIKE_BRAND_IN_SUBDOMAIN"].evidence["location"] == "URL"
    assert ident.checked_hosts == 1


def test_mailer_fingerprints():
    assert fingerprint("Leaf PHPMailer 2.8").category == "phishing-kit"
    assert fingerprint("PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)").category == "script"
    assert fingerprint("PHP/8.1.2").category == "script"
    assert fingerprint("Microsoft Outlook 16.0").category == "client"
    assert fingerprint("Microsoft Outlook Express 6.00.2900.2180").category == "outdated"
    assert fingerprint("Gammadyne Mass E-Mailer v.8").category == "bulk"
    assert fingerprint("SomethingElse/1.0") is None
    ident, found = identity(msg("From: a@x.test\nX-Mailer: Leaf PHPMailer 2.8"))
    assert "HDR_MAILER_PHISHING_KIT" in found and ident.mailer_category == "phishing-kit"


def test_php_script_header():
    ident, found = identity(msg("From: a@x.test\nX-PHP-Originating-Script: 33:mailer.php"))
    assert "HDR_PHP_SCRIPT" in found and ident.php_script == "33:mailer.php"


def test_provider_path_mismatch():
    raw = msg("From: someone@gmail.com\nMessage-ID: <CAx@mail.gmail.com>\n"
              "Received: from vps.evil.test (vps.evil.test [198.51.100.9]) by mx.victim.test; Tue, 22 Sep 2026 10:00:00 +0000")
    _, found = identity(raw)
    assert {"HDR_PROVIDER_PATH_MISMATCH", "HDR_MESSAGE_ID_PROVIDER_MISMATCH"} <= set(found)

    raw = msg("From: someone@gmail.com\nMessage-ID: <CAx@mail.gmail.com>\n"
              "Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.victim.test; "
              "Tue, 22 Sep 2026 10:00:00 +0000")
    _, found = identity(raw)
    assert not {"HDR_PROVIDER_PATH_MISMATCH", "HDR_MESSAGE_ID_PROVIDER_MISMATCH"} & set(found)

    _, found = identity(msg("From: someone@gmail.com"))  # no hops: nothing to compare
    assert "HDR_PROVIDER_PATH_MISMATCH" not in found


def test_microsoft365_verdicts():
    raw = msg("From: ceo@acme-corp.com\nTo: ap@acme-corp.com\n"
              "X-Forefront-Antispam-Report: CIP:198.51.100.9;CTRY:NG;LANG:en;SCL:5;SRV:;IPV:NLI;SFV:SPM;"
              "H:vps.evil.test;PTR:;CAT:SPOOF;SFS:(13230022)(4636009);DIR:INB;\n"
              "X-MS-Exchange-Organization-AuthAs: Anonymous\n"
              "X-Microsoft-Antispam: BCL:0;")
    ident, found = identity(raw)
    assert {"PROVIDER_PHISH_VERDICT", "PROVIDER_EXTERNAL_CLAIMS_INTERNAL"} <= set(found)
    ms = ident.provider_verdicts["microsoft365"]
    assert ms["CAT"] == "SPOOF" and ms["CTRY"] == "NG" and ms["AuthAs"] == "Anonymous" and ms["BCL"] == "0"


def test_microsoft365_spam_bulk_and_bypass():
    _, found = identity(msg("From: a@x.test\nX-MS-Exchange-Organization-SCL: 6"))
    assert "PROVIDER_SPAM_VERDICT" in found
    _, found = identity(msg("From: a@x.test\nX-Microsoft-Antispam: BCL:8;"))
    assert "PROVIDER_BULK_VERDICT" in found
    _, found = identity(msg("From: a@x.test\nX-Forefront-Antispam-Report: SFV:SKN;SCL:-1;"))
    assert "PROVIDER_FILTER_BYPASSED" in found and "PROVIDER_SPAM_VERDICT" not in found


def test_spamassassin():
    ident, found = identity(msg("From: a@x.test\nX-Spam-Status: Yes, score=9.1 required=5.0 tests=BAYES_99"))
    assert "PROVIDER_SPAM_VERDICT" in found and ident.provider_verdicts["spamassassin"]["score"] == "9.1"
    _, found = identity(msg("From: a@x.test\nX-Spam-Status: No, score=0.1 required=5.0"))
    assert "PROVIDER_SPAM_VERDICT" not in found


def test_parse_forefront():
    assert parse_forefront("CIP:1.2.3.4;SCL:1;junk;:x;CAT:NONE") == {"CIP": "1.2.3.4", "SCL": "1", "CAT": "NONE"}


def test_fixtures(fixture_path):
    phish = analyze_file(fixture_path("phish_html.eml"))
    codes = {f.code for f in phish.findings}
    assert {"LOOKALIKE_COMBO", "LOOKALIKE_BRAND_IN_SUBDOMAIN", "LOOKALIKE_HOMOGLYPH",
            "HDR_DISPLAY_NAME_BRAND"} <= codes
    legit = analyze_file(fixture_path("legit.eml"))
    assert not [f for f in legit.findings if f.severity.value != "info"]
    assert legit.identity.mailer_category == "client"
    bec = analyze_file(fixture_path("bec_spoof.eml"))
    assert {"HDR_PROVIDER_PATH_MISMATCH", "HDR_MAILER_SCRIPT"} <= {f.code for f in bec.findings}


def test_protected_domains_via_cli(fixture_path, tmp_path, capsys):
    import json
    from email_forensics.cli import main
    listing = tmp_path / "domains.txt"
    listing.write_text("# partners\nexamp1e.com\n\n")
    main(["analyze", "--json", "--protected-domains-file", str(listing), "--protected-domain", "other.test",
          str(fixture_path("legit.eml"))])
    data = json.loads(capsys.readouterr().out)
    assert "LOOKALIKE_HOMOGLYPH" in {f["code"] for f in data["findings"]}  # example.com vs examp1e.com
    assert main(["analyze", "--protected-domains-file", str(tmp_path / "missing.txt"),
                 str(fixture_path("legit.eml"))]) == 2
