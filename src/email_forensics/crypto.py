"""Minimal, dependency-free public-key crypto for verification and report signing.

- RSA signature verification (PKCS#1 v1.5) for DKIM/ARC ``rsa-sha256`` / ``rsa-sha1``
- Ed25519 (RFC 8032) verification for DKIM ``ed25519-sha256`` and signing for reports

Verification-only RSA is simple and safe in pure Python (no secret data is handled).
Ed25519 follows the RFC 8032 reference algorithm; it is not constant-time, which is
acceptable for verification and for signing reports on an investigator's machine,
but it should not be used to protect keys on shared or hostile systems.
"""

from __future__ import annotations

import hashlib

# --------------------------------------------------------------------------- DER


class CryptoError(ValueError):
    pass


def _der_read(data: bytes, pos: int) -> tuple[int, bytes, int]:
    """Read one DER TLV at pos; return (tag, value, next_pos)."""
    if pos + 2 > len(data):
        raise CryptoError("truncated DER")
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise CryptoError("bad DER length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise CryptoError("truncated DER value")
    return tag, data[pos:pos + length], pos + length


def _der_sequence(data: bytes) -> list[tuple[int, bytes]]:
    tag, value, _ = _der_read(data, 0)
    if tag != 0x30:
        raise CryptoError("expected SEQUENCE")
    items, pos = [], 0
    while pos < len(value):
        t, v, pos = _der_read(value, pos)
        items.append((t, v))
    return items


def parse_rsa_public_key(der: bytes) -> tuple[int, int]:
    """Parse SubjectPublicKeyInfo or bare RSAPublicKey DER into (n, e)."""
    items = _der_sequence(der)
    if len(items) == 2 and items[0][0] == 0x02 and items[1][0] == 0x02:  # RSAPublicKey
        n, e = (int.from_bytes(v, "big") for _, v in items)
    elif len(items) == 2 and items[0][0] == 0x30 and items[1][0] == 0x03:  # SubjectPublicKeyInfo
        bits = items[1][1]
        if not bits or bits[0] != 0:
            raise CryptoError("unexpected BIT STRING padding")
        return parse_rsa_public_key(bits[1:])
    else:
        raise CryptoError("not an RSA public key")
    if n <= 0 or e <= 1:
        raise CryptoError("invalid RSA key")
    return n, e


# --------------------------------------------------------------------------- RSA

_DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
}


def rsa_verify(n: int, e: int, signature: bytes, digest: bytes, hash_name: str) -> bool:
    """Verify an RSASSA-PKCS1-v1_5 signature over a precomputed digest."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k or hash_name not in _DIGEST_INFO:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = _DIGEST_INFO[hash_name] + digest
    pad = k - len(t) - 3
    if pad < 8:
        return False
    return em == b"\x00\x01" + b"\xff" * pad + b"\x00" + t


# --------------------------------------------------------------------------- Ed25519 (RFC 8032)

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _point_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = 2 * t1 * t2 * _D % _P
    D = 2 * z1 * z2 % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _point_mul(s: int, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_equal(a, b) -> bool:
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(p) -> bytes:
    x, y, z, _ = p
    zi = _inv(z)
    x, y = x * zi % _P, y * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _sha512_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _secret_expand(secret: bytes) -> tuple[int, bytes]:
    if len(secret) != 32:
        raise CryptoError("Ed25519 private key must be 32 bytes")
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public_key(secret: bytes) -> bytes:
    a, _ = _secret_expand(secret)
    return _compress(_point_mul(a, _G))


def ed25519_sign(secret: bytes, message: bytes) -> bytes:
    a, prefix = _secret_expand(secret)
    public = _compress(_point_mul(a, _G))
    r = _sha512_int(prefix + message) % _L
    rs = _compress(_point_mul(r, _G))
    h = _sha512_int(rs + public + message) % _L
    s = (r + h * a) % _L
    return rs + int.to_bytes(s, 32, "little")


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    if a is None:
        return False
    rs = signature[:32]
    r = _decompress(rs)
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = _sha512_int(rs + public + message) % _L
    sb = _point_mul(s, _G)
    ha = _point_mul(h, a)
    return _point_equal(sb, _point_add(r, ha))
