from datetime import datetime, timezone

from email_forensics.headers import (
    parse_authentication_results,
    parse_received,
    parse_received_chain,
)
from email_forensics.loader import parse_bytes
from email_forensics.headers import analyze_headers


def test_parse_received_postfix_style():
    hop = parse_received(
        "from mx.example.org (mx.example.org [209.85.220.41]) by mail.recipient.net "
        "(Postfix) with ESMTPS id 4A1B2C3D for <bob@recipient.net>; Tue, 22 Sep 2026 10:00:05 +0000"
    )
    assert hop.from_host == "mx.example.org"
    assert hop.from_ip == "209.85.220.41"
    assert hop.ip_is_private is False
    assert hop.by_host == "mail.recipient.net"
    assert hop.protocol == "ESMTPS"
    assert hop.id == "4A1B2C3D"
    assert hop.for_address == "bob@recipient.net"
    assert hop.timestamp == datetime(2026, 9, 22, 10, 0, 5, tzinfo=timezone.utc)


def test_parse_received_ignores_words_inside_comments():
    hop = parse_received("by host.local (Postfix, from userid 1000) id 1234; Tue, 22 Sep 2026 10:00:05 +0000")
    assert hop.from_host is None
    assert hop.by_host == "host.local"


def test_parse_received_ipv6():
    hop = parse_received("from a.example (a.example [IPv6:2001:4860:4864::1]) by b.example; Tue, 22 Sep 2026 10:00:05 +0000")
    assert hop.from_ip == "2001:4860:4864::1"


def test_parse_received_garbage_does_not_raise():
    hop = parse_received("(((]]; ;;; from")
    assert hop.timestamp is None


def test_received_chain_is_oldest_first_with_delays():
    hops = parse_received_chain([
        "from b by c; Tue, 22 Sep 2026 10:00:10 +0000",
        "from a by b; Tue, 22 Sep 2026 10:00:00 +0000",
    ])
    assert [h.from_host for h in hops] == ["a", "b"]
    assert [h.index for h in hops] == [1, 2]
    assert hops[0].delay_seconds is None
    assert hops[1].delay_seconds == 10


def test_parse_authentication_results():
    results = parse_authentication_results(
        "mx.google.com; dkim=pass (2048-bit key) header.i=@example.com header.s=s1 header.d=example.com; "
        "spf=softfail (google.com: domain of transitioning x@y.com) smtp.mailfrom=y.com; dmarc=fail (p=NONE) header.from=example.com"
    )
    assert [(r.method, r.result) for r in results] == [("dkim", "pass"), ("spf", "softfail"), ("dmarc", "fail")]
    assert results[0].authserv_id == "mx.google.com"
    assert results[0].properties["header.d"] == "example.com"


def test_encoded_display_name_cannot_inject_address():
    msg = parse_bytes(b"From: =?utf-8?q?Boss_=3Cboss=40bank.com=3E?= <x@evil.test>\n\nhi\n")
    h = analyze_headers(msg)
    assert h.from_address == "x@evil.test"
    assert h.from_display_name == "Boss <boss@bank.com>"
