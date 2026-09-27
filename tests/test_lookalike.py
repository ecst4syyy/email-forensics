import pytest

from email_forensics.lookalike import (build_protected, check_host, decode_idna, edit_distance, scripts,
                                       skeleton)

PROTECTED = build_protected({"acme-corp.com"})


def codes(host, location="From"):
    return {f.code for f in check_host(host, PROTECTED, location)}


@pytest.mark.parametrize("host,code", [
    ("paypa1.com", "LOOKALIKE_HOMOGLYPH"),
    ("rnicrosoft.com", "LOOKALIKE_HOMOGLYPH"),
    ("linkedln.com", "LOOKALIKE_HOMOGLYPH"),
    ("xn--80ak6aa92e.com", "LOOKALIKE_HOMOGLYPH"),  # all-Cyrillic "apple"
    ("xn--pypal-4ve.com", "LOOKALIKE_MIXED_SCRIPT"),  # Cyrillic "а" inside Latin
    ("microsfot.com", "LOOKALIKE_TYPO"),
    ("goggle.com", "LOOKALIKE_TYPO"),
    ("paypal-secure.com", "LOOKALIKE_COMBO"),
    ("securepaypal.net", "LOOKALIKE_COMBO"),
    ("my-paypal.com", "LOOKALIKE_COMBO"),
    ("secure-paypa1.com", "LOOKALIKE_COMBO"),
    ("login.paypal.com.evil.net", "LOOKALIKE_BRAND_IN_SUBDOMAIN"),
    ("paypal.evil.net", "LOOKALIKE_BRAND_IN_SUBDOMAIN"),
    # Organisation (recipient / configured) domains are held to a stricter standard.
    ("acme-corp.co", "LOOKALIKE_TLD_SWAP"),
    ("acme-c0rp.com", "LOOKALIKE_HOMOGLYPH"),
    ("acmecorp.com", "LOOKALIKE_HOMOGLYPH"),
    ("acme-corp-invoices.com", "LOOKALIKE_COMBO"),
    ("acme-c0rp-billing.com", "LOOKALIKE_COMBO"),
])
def test_lookalikes_detected(host, code):
    assert code in codes(host)


@pytest.mark.parametrize("host", [
    "paypal.com", "mail.paypal.com", "acme-corp.com", "sub.acme-corp.com", "example.com",
    "office-supplies.com", "live.example.com", "applebees.com", "apply.com", "amazon.de",
    "google.co.uk", "bit.ly", "192.0.2.1", "[2001:db8::1]", "", None, "localhost",
])
def test_no_false_positives(host):
    assert codes(host) == set()


def test_skeleton_and_helpers():
    assert skeleton("PayPa1") == skeleton("paypal")
    assert skeleton("rnicrosoft") == skeleton("microsoft")
    assert skeleton("ｐａｙｐａｌ") == skeleton("paypal")  # full-width, via NFKD
    assert decode_idna("xn--pypal-4ve.com") == "pаypal.com"
    assert decode_idna("xn--broken!!.com") == "xn--broken!!.com"
    assert scripts("pаypal") == {"LATIN", "CYRILLIC"}
    assert scripts("日本ひらがな") == {"JAPANESE"}
    assert edit_distance("microsoft", "microsfot", 1) == 1  # transposition
    assert edit_distance("paypal", "completelydifferent", 2) == 3  # capped


def test_protected_org_overrides_brand():
    protected = build_protected({"paypal.com"})
    assert [p.kind for p in protected if p.domain == "paypal.com"] == ["org"]
