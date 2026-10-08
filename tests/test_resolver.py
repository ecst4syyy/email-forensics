import io
import json

import pytest

from email_forensics import resolver as r
from fakedns import FakeResolver


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_doh_parsing(monkeypatch):
    payloads = {
        "TXT": {"Status": 0, "Answer": [{"type": 16, "data": '"v=DKIM1; k=rsa; " "p=ABC\\"D"'},
                                        {"type": 5, "data": "alias.example."}]},
        "MX": {"Status": 0, "Answer": [{"type": 15, "data": "10 mx.example.com."}]},
        "A": {"Status": 3},
        "AAAA": {"Status": 2},
    }
    seen = []

    def fake_urlopen(req, timeout):
        seen.append(req.full_url)
        rtype = req.full_url.rsplit("type=", 1)[1]
        return _Resp(json.dumps(payloads[rtype]).encode())

    monkeypatch.setattr(r.urllib.request, "urlopen", fake_urlopen)
    doh = r.DohResolver("https://dns.example/resolve")
    assert doh.query("sel._domainkey.example.com", "TXT") == ['v=DKIM1; k=rsa; p=ABC"D']
    assert doh.query("example.com", "MX") == ["10 mx.example.com"]
    assert doh.query("nx.example.com", "A") == []
    with pytest.raises(r.DnsError):
        doh.query("broken.example.com", "AAAA")
    assert seen[0].startswith("https://dns.example/resolve?name=sel._domainkey.example.com&type=TXT")


def test_doh_network_failure(monkeypatch):
    def boom(req, timeout):
        raise OSError("connection refused")
    monkeypatch.setattr(r.urllib.request, "urlopen", boom)
    with pytest.raises(r.DnsError):
        r.DohResolver().query("example.com", "TXT")


def test_join_txt():
    assert r._join_txt('"a" "b"') == "ab"
    assert r._join_txt("unquoted") == "unquoted"
    assert r._join_txt('"with \\" quote"') == 'with " quote'


def test_recording_caches_and_saves(tmp_path):
    fake = FakeResolver({("a.test", "TXT"): ["x"], ("b.test", "TXT"): TimeoutError("down")})
    rec = r.RecordingResolver(fake)
    assert rec.query("A.test.", "txt") == ["x"] and rec.query("a.test", "TXT") == ["x"]
    with pytest.raises(r.DnsError):
        rec.query("b.test", "TXT")
    assert len(fake.queries) == 2  # second a.test query came from the cache
    path = tmp_path / "rec.json"
    rec.save(path)
    replay = r.ReplayResolver(path)
    assert replay.query("a.test", "TXT") == ["x"]
    with pytest.raises(r.DnsError, match="down"):
        replay.query("b.test", "TXT")
    with pytest.raises(r.DnsError, match="not in recording"):
        replay.query("c.test", "TXT")


def test_system_resolver_unreachable_server_is_temperror():
    pytest.importorskip("dns.resolver")
    res = r.SystemResolver()
    res._resolver.nameservers = ["192.0.2.53"]  # TEST-NET: nothing answers
    res._resolver.lifetime = 0.5
    with pytest.raises(r.DnsError):
        res.query("example.com", "TXT")
