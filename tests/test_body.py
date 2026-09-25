from email_forensics.analyzer import analyze_file
from email_forensics.body import analyze_body
from email_forensics.loader import parse_bytes


def body_codes(raw: bytes):
    _, findings = analyze_body(parse_bytes(raw))
    return {f.code for f in findings}


def html_msg(html: str) -> bytes:
    return b"Content-Type: text/html; charset=utf-8\n\n" + html.encode()


def test_phishing_html_fixture(fixture_path):
    report = analyze_file(fixture_path("phish_html.eml"))
    found = {f.code for f in report.findings}
    assert {
        "URL_TEXT_MISMATCH", "URL_USERINFO", "URL_IP_HOST", "URL_IDN_HOST", "URL_SHORTENER",
        "URL_DANGEROUS_SCHEME", "URL_DEEP_SUBDOMAIN", "HTML_CREDENTIAL_FORM", "HTML_SCRIPT",
        "HTML_EVENT_HANDLERS", "HTML_HIDDEN_TEXT", "HTML_BASE_HREF", "HTML_TRACKING_PIXEL",
        "TEXT_ZERO_WIDTH",
    } <= found
    urls = {u.url: u for u in report.body.urls}
    assert "http://evil.test" in urls and urls["http://evil.test"].sources == ["1.2:script"]
    # Anchor text is what the victim sees, not a destination.
    assert "https://www.paypal.com/signin" not in urls


def test_legit_fixture_has_clean_body(fixture_path):
    report = analyze_file(fixture_path("legit.eml"))
    assert [tb.preview.strip() for tb in report.body.text_bodies] == ["Hi Bob, report attached next week."]
    assert report.body.urls == []


def test_link_text_matching_same_org_is_fine():
    assert "URL_TEXT_MISMATCH" not in body_codes(html_msg('<a href="https://login.bank.com/x">www.bank.com</a>'))
    assert "URL_TEXT_MISMATCH" in body_codes(html_msg('<a href="https://evil.test/x">www.bank.com</a>'))


def test_meta_refresh_and_iframe():
    found = body_codes(html_msg(
        '<meta http-equiv="refresh" content="0;url=https://r.test"><iframe src="https://f.test"></iframe>'
    ))
    assert {"HTML_META_REFRESH", "HTML_EMBEDDED_FRAME"} <= found


def test_non_password_form():
    assert "HTML_FORM" in body_codes(html_msg('<form action="https://x.test"><input name="q"></form>'))


def test_bidi_override_in_body():
    assert "TEXT_BIDI_CONTROL" in body_codes(b"Content-Type: text/plain; charset=utf-8\n\nopen \xe2\x80\xaefdp.exe\n")


def test_emoji_zwj_is_not_flagged():
    raw = "Content-Type: text/plain; charset=utf-8\n\nfamily \U0001F468‍\U0001F469\n".encode()
    assert "TEXT_ZERO_WIDTH" not in body_codes(raw)


def test_image_only_message():
    raw = (b'Content-Type: multipart/related; boundary="R"\n\n'
           b"--R\nContent-Type: text/html\n\n<img src=\"cid:a\">\n"
           b"--R\nContent-Type: image/png\nContent-Transfer-Encoding: base64\n\niVBORw0KGgo=\n--R--\n")
    assert "BODY_IMAGE_ONLY" in body_codes(raw)


def test_charset_problem():
    assert "BODY_CHARSET_PROBLEM" in body_codes(b"Content-Type: text/plain; charset=bogus-9\n\nhi\n")


def test_encoded_word_errors_in_headers(fixture_path):
    found = {f.code for f in analyze_file(fixture_path("malformed.eml")).findings}
    assert "HDR_ENCODED_WORD_ERROR" in found


def test_hostile_charset_in_encoded_word_does_not_crash():
    from email_forensics.headers import analyze_headers
    from email_forensics.rules import run_header_rules
    msg = parse_bytes(b"Subject: =?utf\xd3-8?q?hi?= =?base64?b?aGk=?=\n\nx\n")
    codes = [f.code for f in run_header_rules(msg, analyze_headers(msg))]
    assert codes.count("HDR_ENCODED_WORD_ERROR") == 2
