"""Regenerate tests/fixtures/dkim/ with signatures made by the reference dkimpy library.

Development-only: needs dkimpy, dnspython, cryptography and PyNaCl (not project deps).
Keys are generated fresh and only their public halves are kept (in dns.json, the
recording format ReplayResolver reads).

    python tests/fixtures/build_dkim_fixtures.py
"""

import base64
import json
from pathlib import Path

import dkim
import nacl.signing
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

OUT = Path(__file__).with_name("dkim")
OUT.mkdir(exist_ok=True)

MESSAGE = (
    b"From: Alice <alice@signer.test>\r\n"
    b"To: Bob <bob@receiver.test>\r\n"
    b"Subject: Quarterly   numbers\r\n"
    b"Date: Tue, 22 Sep 2026 10:00:00 +0000\r\n"
    b"Message-ID: <q3@signer.test>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Hi Bob,  \r\n"
    b"the numbers\tare attached.\r\n"
    b"\r\n\r\n"
)

dns_records = {}


def rsa_key(bits):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, base64.b64encode(pub).decode()


def publish(selector, domain, record):
    dns_records[f"{selector}._domainkey.{domain}"] = record


def dnsfunc(name, timeout=5):
    return dns_records.get(name.decode().rstrip("."), "").encode()


rsa_pem, rsa_pub = rsa_key(2048)
publish("s2048", "signer.test", f"v=DKIM1; k=rsa; p={rsa_pub}")
weak_pem, weak_pub = rsa_key(1024)
publish("old", "signer.test", f"v=DKIM1; k=rsa; t=y; p={weak_pub}")
ed_key = nacl.signing.SigningKey.generate()
publish("ed", "signer.test", "v=DKIM1; k=ed25519; p=" + base64.b64encode(bytes(ed_key.verify_key)).decode())
ed_seed = base64.b64encode(bytes(ed_key)).decode().encode()

samples = {
    "rsa_relaxed.eml": dict(selector=b"s2048", privkey=rsa_pem, canonicalize=(b"relaxed", b"relaxed")),
    "rsa_simple.eml": dict(selector=b"s2048", privkey=rsa_pem, canonicalize=(b"simple", b"simple")),
    "ed25519.eml": dict(selector=b"ed", privkey=ed_seed, signature_algorithm=b"ed25519-sha256",
                        canonicalize=(b"relaxed", b"relaxed")),
    "rsa_sha1_length.eml": dict(selector=b"old", privkey=weak_pem, signature_algorithm=b"rsa-sha1",
                                canonicalize=(b"relaxed", b"simple"), length=True),
}
for name, opts in samples.items():
    sig = dkim.sign(MESSAGE, domain=b"signer.test", include_headers=[b"from", b"to", b"subject", b"date",
                    b"message-id"], **opts)
    signed = sig + MESSAGE
    assert dkim.verify(signed, dnsfunc=dnsfunc), name
    (OUT / name).write_bytes(signed)

# ARC: sealed by two forwarders after the original DKIM signature.
arc_pem, arc_pub = rsa_key(2048)
publish("arc", "forwarder1.test", f"v=DKIM1; k=rsa; p={arc_pub}")
arc2_pem, arc2_pub = rsa_key(2048)
publish("arc", "forwarder2.test", f"v=DKIM1; k=rsa; p={arc2_pub}")
msg = (OUT / "rsa_relaxed.eml").read_bytes()
for domain, pem, srv, arc in ((b"forwarder1.test", arc_pem, b"mx.forwarder1.test", b""),
                              (b"forwarder2.test", arc2_pem, b"mx.forwarder2.test", b"; arc=pass")):
    msg = (b"Authentication-Results: " + srv + b"; dkim=pass header.d=signer.test" + arc + b"\r\n") + msg
    headers = dkim.arc_sign(msg, b"arc", domain, pem, srv)
    msg = b"".join(headers) + msg
assert dkim.arc_verify(msg, dnsfunc=dnsfunc)[0] == dkim.CV_Pass
(OUT / "arc_two_hops.eml").write_bytes(msg)

lookups = [{"name": n, "type": "TXT", "answers": [r], "error": None, "at": "2026-10-08T00:00:00+00:00"}
           for n, r in sorted(dns_records.items())]
(OUT / "dns.json").write_text(json.dumps({"resolver": "fixture", "lookups": lookups}, indent=2))
print(f"wrote {len(samples) + 1} messages and {len(lookups)} key records to {OUT}")
