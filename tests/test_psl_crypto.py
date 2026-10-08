import hashlib

import pytest

from email_forensics.crypto import (ed25519_public_key, ed25519_sign, ed25519_verify, parse_rsa_public_key,
                                    rsa_verify, CryptoError)
from email_forensics.domains import org_domain
from email_forensics.psl import public_suffix, registrable_domain


@pytest.mark.parametrize("host,expected", [
    ("mail.example.co.uk", "example.co.uk"),
    ("a.b.example.com.au", "example.com.au"),
    ("foo.github.io", "foo.github.io"),         # private-section suffix
    ("city.kawasaki.jp", "city.kawasaki.jp"),   # exception rule
    ("x.y.kawasaki.jp", "x.y.kawasaki.jp"),     # wildcard rule
    ("a.b.www.ck", "www.ck"),
    ("paypal.com.evil.net", "evil.net"),
    ("sub.例え.jp", "例え.jp"),
    ("evil.test", "evil.test"),                 # unlisted TLD: implicit "*" rule
    ("localhost", "localhost"),
    ("co.uk", "co.uk"),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected
    assert org_domain(host) == expected


def test_public_suffix_and_empty():
    assert public_suffix("www.example.co.uk") == "co.uk"
    assert registrable_domain("") is None and registrable_domain(None) is None


# RFC 8032 section 7.1, tests 1 and 2.
@pytest.mark.parametrize("sk,pk,msg,sig", [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
])
def test_ed25519_rfc8032(sk, pk, msg, sig):
    sk, pk, msg, sig = map(bytes.fromhex, (sk, pk, msg, sig))
    assert ed25519_public_key(sk) == pk
    assert ed25519_sign(sk, msg) == sig
    assert ed25519_verify(pk, msg, sig)
    assert not ed25519_verify(pk, msg + b"x", sig)
    assert not ed25519_verify(pk, msg, sig[:-1] + bytes([sig[-1] ^ 1]))
    assert not ed25519_verify(pk[:31], msg, sig)


# A 512-bit test key (insecure; only to exercise the math): n, e, d.
N = int("c5e3a9c8d4f9b3e5e8f0a5c6d7b2a1f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9"
        "a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1", 16)


def test_rsa_verify_rejects_garbage():
    assert not rsa_verify(N, 65537, b"\x00" * 64, hashlib.sha256(b"x").digest(), "sha256")
    assert not rsa_verify(N, 65537, b"\x01" * 10, hashlib.sha256(b"x").digest(), "sha256")
    assert not rsa_verify(N, 65537, b"\x01" * 64, hashlib.md5(b"x").digest(), "md5")


def test_parse_rsa_public_key_errors():
    for bad in (b"", b"\x30\x03\x02\x01", b"\x04\x00", b"\x30\x80"):
        with pytest.raises(CryptoError):
            parse_rsa_public_key(bad)
