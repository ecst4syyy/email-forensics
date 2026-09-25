from email_forensics.models import Link
from email_forensics.urls import collect_urls, extract_text_urls, link_text_host, url_findings


def codes_for(url):
    [info] = collect_urls([Link(url=url, source="a", part="1")])
    return {f.code for f in url_findings(info)}


def test_extract_text_urls_strips_punctuation():
    urls = [l.url for l in extract_text_urls("See https://a.test/x). Or www.b.test, ok", "1")]
    assert urls == ["https://a.test/x", "www.b.test"]


def test_collect_urls_dedupes_and_skips_non_urls():
    infos = collect_urls([
        Link("https://a.test/", "a", "1", "A"),
        Link("https://a.test/", "text", "2"),
        Link("mailto:x@y.test", "a", "1"),
        Link("#top", "a", "1"),
        Link("/relative", "a", "1"),
    ])
    assert len(infos) == 1
    assert infos[0].sources == ["1:a", "2:text"]
    assert infos[0].anchor_texts == ["A"]
    assert infos[0].org_domain == "a.test"


def test_url_heuristics():
    assert "URL_USERINFO" in codes_for("http://paypal.com@evil.test/")
    assert "URL_IP_HOST" in codes_for("http://192.0.2.1/login")
    assert "URL_IP_HOST" in codes_for("http://3232235777/")  # decimal IP 192.168.1.1
    assert "URL_IDN_HOST" in codes_for("https://xn--pypal-4ve.com/")
    assert "URL_SHORTENER" in codes_for("https://bit.ly/abc")
    assert "URL_NONSTANDARD_PORT" in codes_for("http://a.test:8080/")
    assert "URL_DEEP_SUBDOMAIN" in codes_for("http://a.b.c.d.evil.test/")
    assert "URL_DANGEROUS_SCHEME" in codes_for("javascript:alert(1)")
    assert "URL_DANGEROUS_SCHEME" in codes_for("data:text/html;base64,PHNjcmlwdD4=")
    assert codes_for("https://www.example.com/path?q=1") == set()


def test_malformed_url_does_not_raise():
    codes_for("http://[::1/")
    codes_for("http://a.test:99999999/")


def test_link_text_host():
    assert link_text_host("https://www.paypal.com/signin") == "paypal.com"
    assert link_text_host("paypal.com") == "paypal.com"
    assert link_text_host("Click here") is None
    assert link_text_host("invoice.pdf") is None
    assert link_text_host("www.report.pdf") == "report.pdf"
