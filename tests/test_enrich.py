import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from email_forensics.analyzer import AnalysisOptions, analyze_message
from email_forensics.cli import main
from email_forensics.enrich import Enricher, FetchError, Fetcher, Recorder, ReplayFetcher, _targets
from email_forensics.iocs import Indicator
from email_forensics.loader import load_evidence
from email_forensics.resolver import RecordingResolver
from fakedns import FakeResolver

FIX = Path(__file__).parent / "fixtures"
SHA = "a" * 64

RESPONSES = {
    ("GET", "https://rdap.org/domain/secure-paypa1.com"): {
        "events": [{"eventAction": "registration", "eventDate": "2026-09-20T12:00:00Z"},
                   {"eventAction": "expiration", "eventDate": "2027-09-20T12:00:00Z"}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                                        ["fn", {}, "text", "NameCheap, Inc."]]]}],
        "status": ["client transfer prohibited"]},
    ("GET", "https://rdap.org/domain/paypal.com"): {"events": [{"eventAction": "registration", "eventDate": "1999-07-15T05:32:11Z"}]},
    ("GET", "https://www.virustotal.com/api/v3/files/" + SHA): {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 0},
                                "popular_threat_classification": {"suggested_threat_label": "trojan.emotet"}}}},
    ("POST", "https://urlhaus-api.abuse.ch/v1/url/"): {"query_status": "ok", "threat": "malware_download", "url_status": "online"},
    ("POST", "https://urlhaus-api.abuse.ch/v1/host/"): {"query_status": "no_results"},
    ("POST", "https://mb-api.abuse.ch/api/v1/"): {"query_status": "ok", "data": [{"signature": "AgentTesla", "file_type": "exe"}]},
}


class FakeFetcher(Fetcher):
    name = "fake"

    def __init__(self, responses=RESPONSES, fail=()):
        self.responses, self.fail, self.calls = responses, set(fail), []

    def request(self, method, url, headers=None, data=None):
        self.calls.append((method, url, headers, data))
        if url in self.fail:
            raise FetchError("HTTP 500")
        for (m, prefix), resp in self.responses.items():
            if m == method and url.startswith(prefix):
                return resp
        return {"_status": 404}


def indicators(*items):
    return [Indicator(t, v, "x", "0" * 64, "malicious") for t, v in items]


def test_targets_filtering():
    t = _targets(indicators(("ipv4", "10.0.0.1"), ("ipv4", "81.2.69.160"), ("domain", "mail.paypal.com"),
                            ("url", "https://x.test/a"), ("sha256", SHA.upper()), ("subject", "hi")))
    assert t == [("ip", "81.2.69.160"), ("domain", "paypal.com"), ("url", "https://x.test/a"), ("sha256", SHA)]


def test_rdap_new_domain_relative_to_message_date():
    e = Enricher(FakeFetcher(), providers=["rdap"], sleep=lambda s: None)
    sent = datetime(2026, 9, 23, 8, 0, tzinfo=timezone.utc)
    result, findings = e.enrich(indicators(("domain", "secure-paypa1.com"), ("domain", "paypal.com")), sent)
    [new] = [f for f in findings if f.code == "ENRICH_NEW_DOMAIN"]
    assert new.severity.value == "high" and new.evidence["age_days"] < 3 and new.evidence["registrar"] == "NameCheap, Inc."
    assert {r.value for r in result.records} == {"secure-paypa1.com", "paypal.com"}


def test_keyed_providers_need_keys(monkeypatch):
    for k in ("VT_API_KEY", "ABUSE_CH_API_KEY", "URLHAUS_API_KEY", "ABUSEIPDB_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    result, _ = Enricher(FakeFetcher(), sleep=lambda s: None).enrich(indicators(("sha256", SHA)))
    assert result.providers == ["rdap"]
    assert any(s.startswith("virustotal: set VT_API_KEY") for s in result.skipped)
    assert any(s.startswith("cymru: needs DNS") for s in result.skipped)


def test_reputation_findings_and_secret_handling(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_API_KEY", "vt-secret-123")
    monkeypatch.setenv("ABUSE_CH_API_KEY", "abuse-secret-456")
    fake = FakeFetcher()
    rec = Recorder(fake, cache_dir=tmp_path / "cache")
    e = Enricher(rec, providers=["virustotal", "urlhaus", "malwarebazaar"], sleep=lambda s: None)
    _, findings = e.enrich(indicators(("sha256", SHA), ("url", "http://203.0.113.9/a.exe")))
    codes = {f.code for f in findings}
    assert {"ENRICH_KNOWN_MALWARE", "ENRICH_URLHAUS_LISTED"} <= codes
    assert any(h and h.get("x-apikey") == "vt-secret-123" for _, _, h, _ in fake.calls)  # sent to the API...
    out = tmp_path / "rec.json"
    rec.save(out)
    stored = out.read_text() + "".join(p.read_text() for p in (tmp_path / "cache").glob("*.json"))
    assert "vt-secret-123" not in stored and "abuse-secret-456" not in stored  # ...but never recorded


def test_cache_and_replay(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "k")
    fake = FakeFetcher()
    first = Recorder(fake, cache_dir=tmp_path)
    Enricher(first, providers=["virustotal"], sleep=lambda s: None).enrich(indicators(("sha256", SHA)))
    calls = len(fake.calls)
    second = Recorder(fake, cache_dir=tmp_path)
    Enricher(second, providers=["virustotal"], sleep=lambda s: None).enrich(indicators(("sha256", SHA)))
    assert len(fake.calls) == calls and second.log[0].cached
    first.save(tmp_path / "rec.json")
    replay = Enricher(ReplayFetcher(tmp_path / "rec.json"), providers=["virustotal"], sleep=lambda s: None)
    _, findings = replay.enrich(indicators(("sha256", SHA)))
    assert "ENRICH_KNOWN_MALWARE" in {f.code for f in findings}


def test_rate_limit_lookup_cap_and_errors(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "k")
    sleeps = []
    hashes = [f"{i:064x}" for i in range(5)]
    fake = FakeFetcher(fail={"https://www.virustotal.com/api/v3/files/" + hashes[1]})
    e = Enricher(fake, providers=["virustotal"], sleep=sleeps.append, max_lookups=3)
    result, findings = e.enrich(indicators(*(("sha256", h) for h in hashes)))
    assert len(fake.calls) == 3 and len(sleeps) == 2 and all(s > 10 for s in sleeps)  # 4/min public API
    assert any("lookup limit" in s for s in result.skipped)
    assert any(f.code == "ENRICH_ERRORS" for f in findings)


def test_cymru_over_dns():
    resolver = FakeResolver({
        ("160.69.2.81.origin.asn.cymru.com", "TXT"): ["20712 | 81.2.64.0/19 | GB | ripencc | 2003-07-01"],
        ("AS20712.asn.cymru.com", "TXT"): ["20712 | GB | ripencc | 2001-06-12 | ANDREWS-ARNOLD, GB"],
    })
    e = Enricher(FakeFetcher(), resolver=resolver, providers=["cymru"], sleep=lambda s: None)
    result, findings = e.enrich(indicators(("ipv4", "81.2.69.160")))
    assert result.records[0].summary == {"asn": "20712", "prefix": "81.2.64.0/19", "country": "GB",
                                         "registry": "ripencc", "as_name": "ANDREWS-ARNOLD, GB"}
    assert findings[0].code == "ENRICH_IP_ASN"


def test_abuseipdb(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    fake = FakeFetcher({("GET", "https://api.abuseipdb.com/api/v2/check?"): {
        "data": {"abuseConfidenceScore": 100, "totalReports": 321, "isp": "Evil Hosting", "countryCode": "NL"}}})
    _, findings = Enricher(fake, providers=["abuseipdb"], sleep=lambda s: None).enrich(indicators(("ipv4", "81.2.69.160")))
    assert findings[0].code == "ENRICH_ABUSIVE_IP" and findings[0].severity.value == "high"


def test_unknown_provider():
    with pytest.raises(ValueError, match="unknown enrichment provider"):
        Enricher(FakeFetcher(), providers=["shodan"])


def test_end_to_end_affects_score(monkeypatch):
    evidence, raw, msg, _ = load_evidence(FIX / "phish_html.eml")
    base = analyze_message(evidence, raw, msg, AnalysisOptions())
    e = Enricher(FakeFetcher(), resolver=RecordingResolver(FakeResolver({})), providers=["rdap"], sleep=lambda s: None)
    enriched = analyze_message(evidence, raw, msg, AnalysisOptions(enricher=e))
    assert "ENRICH_NEW_DOMAIN" in {f.code for f in enriched.findings}
    assert enriched.assessment.score >= base.assessment.score
    assert enriched.enrichment.requests and all("rdap.org" in r.request for r in enriched.enrichment.requests)


def test_cli_replay(tmp_path, capsys):
    recording = {"requests": [{"provider": "rdap", "request": "GET https://rdap.org/domain/secure-paypa1.com",
                               "at": "2026-10-01T00:00:00+00:00", "response": RESPONSES[("GET", "https://rdap.org/domain/secure-paypa1.com")],
                               "error": None, "cached": False}]}
    path = tmp_path / "enrich.json"
    path.write_text(json.dumps(recording))
    assert main(["analyze", "--json", "--enrich-replay", str(path), "--enrich-providers", "rdap",
                 str(FIX / "phish_html.eml")]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "ENRICH_NEW_DOMAIN" in {f["code"] for f in data["findings"]}
    assert main(["analyze", "--enrich-record", "x.json", str(FIX / "legit.eml")]) == 2


def test_http_fetcher(monkeypatch):
    import io
    import urllib.error
    from email_forensics import enrich

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    seen = {}

    def ok(req, timeout):
        seen["ua"] = req.get_header("User-agent")
        seen["body"] = req.data
        return Resp(b'{"query_status": "ok"}')

    monkeypatch.setattr(enrich.urllib.request, "urlopen", ok)
    f = enrich.HttpFetcher()
    assert f.request("POST", "https://x.test/", data={"url": "http://a.test"}) == {"query_status": "ok"}
    assert seen["ua"].startswith("email-forensics/") and seen["body"] == b"url=http%3A%2F%2Fa.test"

    def not_found(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 404, "nf", {}, None)
    monkeypatch.setattr(enrich.urllib.request, "urlopen", not_found)
    assert f.request("GET", "https://x.test/") == {"_status": 404}

    def server_error(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 429, "slow down", {}, None)
    monkeypatch.setattr(enrich.urllib.request, "urlopen", server_error)
    with pytest.raises(FetchError, match="429"):
        f.request("GET", "https://x.test/")

    monkeypatch.setattr(enrich.urllib.request, "urlopen", lambda req, timeout: Resp(b"x" * (enrich.MAX_RESPONSE + 10)))
    with pytest.raises(FetchError, match="too large"):
        f.request("GET", "https://x.test/")
    monkeypatch.setattr(enrich.urllib.request, "urlopen", lambda req, timeout: Resp(b"<html>"))
    with pytest.raises(FetchError, match="not JSON"):
        f.request("GET", "https://x.test/")
