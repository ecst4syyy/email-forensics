from pathlib import Path

import pytest

from email_forensics.dkimcheck import (canon_body, canon_header, parse_tags, split_message, verify_arc,
                                       verify_dkim, DkimSyntaxError, RawHeader)
from email_forensics.resolver import ReplayResolver
from fakedns import FakeResolver

DKIM = Path(__file__).parent / "fixtures" / "dkim"
SIGNED = ["rsa_relaxed.eml", "rsa_simple.eml", "ed25519.eml", "rsa_sha1_length.eml", "arc_two_hops.eml"]


@pytest.fixture
def resolver():
    return ReplayResolver(DKIM / "dns.json")


@pytest.mark.parametrize("name", SIGNED)
def test_reference_signatures_verify(name, resolver):
    # Fixtures were signed by the independent dkimpy library.
    [res] = verify_dkim((DKIM / name).read_bytes(), resolver)
    assert res.result == "pass", res.reason
    assert res.body_hash_ok and res.domain == "signer.test"


@pytest.mark.parametrize("name", SIGNED)
def test_lf_line_endings_still_verify(name, resolver):
    raw = (DKIM / name).read_bytes().replace(b"\r\n", b"\n")
    assert verify_dkim(raw, resolver)[0].result == "pass"


@pytest.mark.parametrize("name", SIGNED)
def test_body_tampering_detected_offline(name):
    raw = (DKIM / name).read_bytes().replace(b"the numbers", b"the NUMBERS")
    [res] = verify_dkim(raw, None)
    assert res.body_hash_ok is False and res.result == "fail"


@pytest.mark.parametrize("name", SIGNED)
def test_header_tampering_detected_online(name, resolver):
    raw = (DKIM / name).read_bytes().replace(b"Subject: Quarterly", b"Subject: Urgent")
    [res] = verify_dkim(raw, resolver)
    assert res.body_hash_ok and res.result == "fail" and "signature mismatch" in res.reason


def test_offline_result_is_neutral():
    [res] = verify_dkim((DKIM / "rsa_relaxed.eml").read_bytes(), None)
    assert res.result == "neutral" and res.body_hash_ok


def test_relaxed_canonicalisation_ignores_whitespace_changes(resolver):
    raw = (DKIM / "rsa_relaxed.eml").read_bytes()
    raw = raw.replace(b"Subject: Quarterly   numbers", b"Subject:   Quarterly numbers  ")
    raw = raw.replace(b"Hi Bob,  \r\n", b"Hi   Bob,\r\n")
    assert verify_dkim(raw, resolver)[0].result == "pass"


def test_simple_canonicalisation_is_strict(resolver):
    raw = (DKIM / "rsa_simple.eml").read_bytes().replace(b"Quarterly   numbers", b"Quarterly numbers")
    assert verify_dkim(raw, resolver)[0].result == "fail"


def test_length_limit_allows_appended_content(resolver):
    raw = (DKIM / "rsa_sha1_length.eml").read_bytes() + b"Click http://evil.test now\r\n"
    [res] = verify_dkim(raw, resolver)
    assert res.result == "pass" and res.body_length_limit is not None


def test_key_problems():
    raw = (DKIM / "rsa_relaxed.eml").read_bytes()
    assert verify_dkim(raw, FakeResolver({}))[0].result == "permerror"  # no key: rotated/removed
    revoked = FakeResolver({("s2048._domainkey.signer.test", "TXT"): ["v=DKIM1; p="]})
    assert "revoked" in verify_dkim(raw, revoked)[0].reason
    broken = FakeResolver({("s2048._domainkey.signer.test", "TXT"): TimeoutError("timeout")})
    assert verify_dkim(raw, broken)[0].result == "temperror"
    garbage = FakeResolver({("s2048._domainkey.signer.test", "TXT"): ["v=DKIM1; p=AAAA"]})
    assert verify_dkim(raw, garbage)[0].result == "permerror"


def test_wrong_key_fails(resolver):
    # Ed25519 key served for the RSA selector.
    ed = next(lk for lk in __import__("json").loads((DKIM / "dns.json").read_text())["lookups"] if lk["name"].startswith("ed."))
    swapped = FakeResolver({("s2048._domainkey.signer.test", "TXT"): ed["answers"]})
    assert verify_dkim((DKIM / "rsa_relaxed.eml").read_bytes(), swapped)[0].result == "fail"


@pytest.mark.parametrize("header,reason", [
    (b"DKIM-Signature: v=1; a=rsa-sha256; d=x.test; s=s; h=to; bh=AAAA; b=AAAA\r\n", "From header is not signed"),
    (b"DKIM-Signature: v=1; a=rsa-md5; d=x.test; s=s; h=from; bh=AAAA; b=AAAA\r\n", "unsupported algorithm"),
    (b"DKIM-Signature: v=1; a=rsa-sha256; d=x.test; h=from; bh=AAAA; b=AAAA\r\n", "missing required tag s="),
    (b"DKIM-Signature: v=1; v=1; a=rsa-sha256\r\n", "duplicate tag"),
    (b"DKIM-Signature: v=1; a=rsa-sha256; d=x.test; s=s; h=from; i=@evil.test; bh=AAAA; b=AAAA\r\n", "not within"),
    (b"DKIM-Signature: garbage\r\n", "malformed tag"),
])
def test_malformed_signatures(header, reason):
    [res] = verify_dkim(header + b"From: a@x.test\r\n\r\nbody\r\n", None)
    assert res.result == "permerror" and reason in res.reason


def test_signature_limit_and_unsigned():
    assert verify_dkim(b"From: a@x.test\r\n\r\nhi\r\n", None) == []
    many = b"".join(b"DKIM-Signature: v=1\r\n" for _ in range(50)) + b"From: a@x.test\r\n\r\n"
    assert len(verify_dkim(many, None)) == 10


def test_canonicalisation_rules():
    assert canon_body(b"", "simple") == b"\r\n"
    assert canon_body(b"", "relaxed") == b""
    assert canon_body(b"a  b \t\r\n\r\n\r\n", "relaxed") == b"a b\r\n"
    assert canon_body(b"a  b \r\n\r\n", "simple") == b"a  b \r\n"
    assert canon_header(RawHeader("Subject", b"SubJect :  A \r\n\t B  \r\n"), "relaxed") == b"subject:A B\r\n"
    fields, body = split_message(b"A: 1\nB: 2\n continued\n\nbody\n")
    assert [f.name for f in fields] == ["A", "B"] and fields[1].raw == b"B: 2\r\n continued\r\n"
    assert body == b"body\r\n"
    with pytest.raises(DkimSyntaxError):
        parse_tags("a=1; 9x=2")


def test_arc_chain(resolver):
    raw = (DKIM / "arc_two_hops.eml").read_bytes()
    arc = verify_arc(raw, resolver)
    assert arc.result == "pass" and arc.instances == 2
    assert [s["d"] for s in arc.sealers] == ["forwarder1.test", "forwarder2.test"]
    assert verify_arc(raw, None).result == "neutral"


def test_arc_tampering(resolver):
    raw = (DKIM / "arc_two_hops.eml").read_bytes()
    assert verify_arc(raw.replace(b"the numbers", b"the NUMBERS"), resolver).result == "fail"
    # Altering the first hop's recorded results breaks its seal.
    tampered = raw.replace(b"i=1; mx.forwarder1.test;\r\n dkim=pass", b"i=1; mx.forwarder1.test;\r\n dkim=fail", 1)
    assert tampered != raw and verify_arc(tampered, resolver).result == "fail"
    # Dropping an instance breaks the structure.
    lines = raw.split(b"\r\n")
    no_i1 = b"\r\n".join(l for l in lines if not (l.startswith(b"ARC-Seal: i=1") or l.startswith(b"ARC-Seal:i=1")))
    assert verify_arc(no_i1, resolver).result == "fail"
    assert verify_arc(b"From: a@x.test\r\n\r\nhi", resolver).result == "none"
    # The plain Authentication-Results header is not covered by any seal.
    unsealed = raw.replace(b"Authentication-Results: mx.forwarder1.test; dkim=pass",
                           b"Authentication-Results: mx.forwarder1.test; dkim=fail")
    assert verify_arc(unsealed, resolver).result == "pass"
