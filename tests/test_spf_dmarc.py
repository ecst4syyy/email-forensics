import pytest

from email_forensics.dmarc import check_dmarc
from email_forensics.spf import check_spf
from fakedns import FakeResolver

BASE = {
    ("example.com", "TXT"): ["v=spf1 ip4:192.0.2.0/24 include:_spf.esp.test mx a:web.example.com ~all", "other"],
    ("_spf.esp.test", "TXT"): ["v=spf1 ip6:2001:db8::/32 ip4:198.51.100.7 -all"],
    ("example.com", "MX"): ["10 mx1.example.com"],
    ("mx1.example.com", "A"): ["203.0.113.25"],
    ("web.example.com", "A"): ["203.0.113.80"],
    ("strict.test", "TXT"): ["v=spf1 -all"],
    ("redir.test", "TXT"): ["v=spf1 redirect=example.com"],
    ("macro.test", "TXT"): ["v=spf1 exists:%{ir}.%{l}._spf.macro.test -all"],
    ("1.2.0.192.alice._spf.macro.test", "A"): ["127.0.0.2"],
    ("two.test", "TXT"): ["v=spf1 -all", "v=spf1 +all"],
    ("loop.test", "TXT"): ["v=spf1 include:loop.test"],
    ("many.test", "TXT"): ["v=spf1 " + " ".join(f"a:h{i}.many.test" for i in range(11)) + " -all"],
    **{(f"h{i}.many.test", "A"): ["203.0.113.1"] for i in range(11)},
    ("bad.test", "TXT"): ["v=spf1 foo:bar -all"],
    ("temp.test", "TXT"): TimeoutError("SERVFAIL"),
}


def spf(ip, sender, records=BASE, helo=None):
    return check_spf(FakeResolver(records), ip, sender, helo)


@pytest.mark.parametrize("ip,sender,result,mech", [
    ("192.0.2.10", "a@example.com", "pass", "+ip4:192.0.2.0/24"),
    ("198.51.100.7", "a@example.com", "pass", "+include:_spf.esp.test"),
    ("2001:db8::25", "a@example.com", "pass", "+include:_spf.esp.test"),
    ("203.0.113.25", "a@example.com", "pass", "+mx"),
    ("203.0.113.80", "a@example.com", "pass", "+a:web.example.com"),
    ("8.8.8.8", "a@example.com", "softfail", "~all"),
    ("8.8.8.8", "a@strict.test", "fail", "-all"),
    ("192.0.2.10", "a@redir.test", "pass", "+ip4:192.0.2.0/24"),
    ("192.0.2.1", "alice@macro.test", "pass", "+exists:%{ir}.%{l}._spf.macro.test"),
    ("192.0.2.9", "bob@macro.test", "fail", "-all"),
])
def test_spf_results(ip, sender, result, mech):
    res = spf(ip, sender)
    assert (res.result, res.mechanism) == (result, mech), res.reason


@pytest.mark.parametrize("sender,result,reason", [
    ("a@nospf.test", "none", "no SPF record"),
    ("a@two.test", "permerror", "2 SPF records"),
    ("a@loop.test", "permerror", ""),
    ("a@many.test", "permerror", "DNS-querying terms"),
    ("a@bad.test", "permerror", "unknown mechanism"),
    ("a@temp.test", "temperror", "SERVFAIL"),
])
def test_spf_errors(sender, result, reason):
    res = spf("192.0.2.1", sender)
    assert res.result == result and reason in res.reason


def test_spf_helo_fallback_and_bad_ip():
    res = spf("8.8.8.8", None, helo="strict.test")
    assert res.identity == "helo" and res.result == "fail"
    assert spf("not-an-ip", "a@example.com").result == "permerror"
    assert spf("8.8.8.8", None).result == "none"


def test_spf_void_lookup_limit():
    records = {("void.test", "TXT"): ["v=spf1 a:x1.void.test a:x2.void.test a:x3.void.test -all"]}
    assert "void lookups" in spf("192.0.2.1", "a@void.test", records).reason


DMARC = {
    ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; sp=quarantine; adkim=s; pct=50"],
    ("_dmarc.relaxed.test", "TXT"): ["v=DMARC1; p=none"],
    ("_dmarc.broken.test", "TXT"): ["v=DMARC1; p=maybe"],
}


def dmarc(from_domain, dkim=(), spf_result=None, spf_domain=None):
    return check_dmarc(FakeResolver(DMARC), from_domain, list(dkim), spf_result, spf_domain)


def test_dmarc_alignment():
    assert dmarc("example.com", dkim=["example.com"]).result == "pass"
    strict = dmarc("example.com", dkim=["mail.example.com"])  # adkim=s
    assert strict.result == "fail" and strict.policy == "reject" and strict.pct == 50
    assert dmarc("example.com", spf_result="pass", spf_domain="bounce.example.com").result == "pass"  # aspf=r
    assert dmarc("example.com", spf_result="fail", spf_domain="example.com").result == "fail"
    assert dmarc("relaxed.test", dkim=["mail.relaxed.test"]).result == "pass"


def test_dmarc_subdomain_policy_and_missing():
    sub = dmarc("news.example.com", dkim=["esp.test"])
    assert sub.result == "fail" and sub.policy_domain == "example.com" and sub.policy == "quarantine"
    assert dmarc("nopolicy.test").result == "none"
    assert dmarc("broken.test").result == "permerror"
    assert dmarc(None).result == "permerror"
    failing = check_dmarc(FakeResolver({("_dmarc.x.test", "TXT"): TimeoutError("x")}), "x.test", [], None, None)
    assert failing.result == "temperror"
