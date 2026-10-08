"""DKIM (RFC 6376, RFC 8463) and ARC (RFC 8617) verification on raw message bytes.

The body-hash check needs no DNS: it shows whether the body still matches what the
signer hashed, i.e. whether it was modified after signing. Signature verification
needs the signer's public key from DNS and is only done when a resolver is given.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .crypto import CryptoError, ed25519_verify, parse_rsa_public_key, rsa_verify
from .resolver import DnsError, Resolver

MAX_SIGNATURES = 10
MAX_ARC_INSTANCES = 50
_ALGORITHMS = {"rsa-sha256": ("rsa", "sha256"), "rsa-sha1": ("rsa", "sha1"), "ed25519-sha256": ("ed25519", "sha256")}
_WSP_RE = re.compile(rb"[ \t]+")
_FWS_RE = re.compile(r"\s+")


class DkimSyntaxError(ValueError):
    pass


# --------------------------------------------------------------------------- message parsing


@dataclass
class RawHeader:
    name: str  # as written
    raw: bytes  # full field including name, folding and trailing CRLF

    @property
    def lname(self) -> str:
        return self.name.strip().lower()

    @property
    def value(self) -> bytes:
        return self.raw.split(b":", 1)[1]


def split_message(raw: bytes) -> tuple[list[RawHeader], bytes]:
    """Split raw bytes into header fields and body, normalising line endings to CRLF."""
    raw = re.sub(rb"(?<!\r)\n", b"\r\n", raw)
    if raw.startswith(b"\r\n"):
        head, body = b"", raw[2:]
    else:
        head, sep, body = raw.partition(b"\r\n\r\n")
        if not sep:
            body = b""
        head += b"\r\n"
    fields: list[RawHeader] = []
    for line in head.split(b"\r\n")[:-1]:
        if line[:1] in (b" ", b"\t") and fields:
            fields[-1].raw += line + b"\r\n"
        elif b":" in line:
            fields.append(RawHeader(line.split(b":", 1)[0].decode("latin-1"), line + b"\r\n"))
    return fields, body


def parse_tags(value: str) -> dict[str, str]:
    """Parse a DKIM tag-list ("a=rsa-sha256; d=example.com; ...")."""
    tags: dict[str, str] = {}
    for item in value.split(";"):
        if not item.strip():
            continue
        if "=" not in item:
            raise DkimSyntaxError(f"malformed tag {item.strip()[:40]!r}")
        name, val = item.split("=", 1)
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
            raise DkimSyntaxError(f"invalid tag name {name[:40]!r}")
        if name in tags:
            raise DkimSyntaxError(f"duplicate tag {name}")
        tags[name] = val.strip()
    return tags


# --------------------------------------------------------------------------- canonicalisation


def canon_header(field: RawHeader, algorithm: str) -> bytes:
    if algorithm == "simple":
        return field.raw
    value = field.value.replace(b"\r\n", b"")
    value = _WSP_RE.sub(b" ", value).strip(b" ")
    return field.lname.encode("latin-1") + b":" + value + b"\r\n"


def canon_body(body: bytes, algorithm: str) -> bytes:
    if algorithm == "simple":
        while body.endswith(b"\r\n\r\n"):
            body = body[:-2]
        return body if body.endswith(b"\r\n") else body + b"\r\n"
    lines = [_WSP_RE.sub(b" ", line).rstrip(b" ") for line in body.split(b"\r\n")]
    text = b"\r\n".join(lines)
    while text.endswith(b"\r\n"):
        text = text[:-2]
    return text + b"\r\n" if text else b""


def _strip_b(field: RawHeader) -> RawHeader:
    """The signature header with the value of its b= tag removed (but not bh=)."""
    name, _, value = field.raw.partition(b":")
    parts = value.split(b";")
    for i, part in enumerate(parts):
        tag = part.split(b"=", 1)[0]
        if tag.strip() == b"b" and b"=" in part:
            parts[i] = part[: part.index(b"=") + 1]
    return RawHeader(field.name, name + b":" + b";".join(parts))


def _select_headers(fields: list[RawHeader], names: list[str]) -> list[RawHeader]:
    """Pick header instances for h=, bottom-up, each instance used at most once."""
    used: set[int] = set()
    out = []
    for name in names:
        name = name.strip().lower()
        for idx in range(len(fields) - 1, -1, -1):
            if idx not in used and fields[idx].lname == name:
                used.add(idx)
                out.append(fields[idx])
                break
    return out


def _b64(value: str) -> bytes:
    try:
        return base64.b64decode(_FWS_RE.sub("", value), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DkimSyntaxError(f"invalid base64: {exc}") from exc


# --------------------------------------------------------------------------- keys


@dataclass
class PublicKey:
    kind: str
    rsa: tuple[int, int] | None = None
    ed25519: bytes | None = None
    hashes: list[str] | None = None
    testing: bool = False
    strict: bool = False
    bits: int | None = None


class KeyError_(Exception):
    def __init__(self, result: str, reason: str) -> None:
        super().__init__(reason)
        self.result, self.reason = result, reason


def fetch_key(resolver: Resolver, selector: str, domain: str) -> PublicKey:
    name = f"{selector}._domainkey.{domain}"
    try:
        records = resolver.query(name, "TXT")
    except DnsError as exc:
        raise KeyError_("temperror", f"key lookup for {name} failed: {exc}") from exc
    records = [r for r in records if "p=" in r]
    if not records:
        raise KeyError_("permerror", f"no key record at {name} (removed or rotated?)")
    try:
        tags = parse_tags(records[0])
    except DkimSyntaxError as exc:
        raise KeyError_("permerror", f"malformed key record: {exc}") from exc
    if tags.get("v", "DKIM1") != "DKIM1":
        raise KeyError_("permerror", "key record has wrong version")
    p = _FWS_RE.sub("", tags.get("p", ""))
    if not p:
        raise KeyError_("permerror", "key has been revoked (empty p=)")
    flags = [f.strip() for f in tags.get("t", "").split(":")]
    key = PublicKey(
        kind=tags.get("k", "rsa").lower(),
        hashes=[h.strip().lower() for h in tags["h"].split(":")] if "h" in tags else None,
        testing="y" in flags, strict="s" in flags,
    )
    try:
        material = base64.b64decode(p, validate=True)
        if key.kind == "rsa":
            key.rsa = parse_rsa_public_key(material)
            key.bits = key.rsa[0].bit_length()
        elif key.kind == "ed25519":
            if len(material) != 32:
                raise CryptoError("Ed25519 key must be 32 bytes")
            key.ed25519, key.bits = material, 256
        else:
            raise KeyError_("permerror", f"unsupported key type {key.kind}")
    except (binascii.Error, ValueError, CryptoError) as exc:
        raise KeyError_("permerror", f"unusable public key: {exc}") from exc
    return key


def _verify_signature(key: PublicKey, algorithm: str, data: bytes, signature: bytes) -> bool:
    kind, hash_name = _ALGORITHMS[algorithm]
    if key.kind != kind:
        return False
    digest = hashlib.new(hash_name, data).digest()
    if kind == "rsa":
        return rsa_verify(*key.rsa, signature, digest, hash_name)
    return ed25519_verify(key.ed25519, digest, signature)


# --------------------------------------------------------------------------- DKIM


@dataclass
class DkimResult:
    domain: str | None = None
    selector: str | None = None
    algorithm: str | None = None
    canonicalization: str | None = None
    identity: str | None = None
    signed_headers: list[str] = field(default_factory=list)
    result: str = "permerror"  # pass, fail, neutral (unverified), permerror, temperror
    reason: str = ""
    body_hash_ok: bool | None = None
    body_length_limit: int | None = None
    key_bits: int | None = None
    key_testing: bool = False
    signed_at: str | None = None
    expires_at: str | None = None
    expired: bool = False


def verify_dkim(raw: bytes, resolver: Resolver | None = None, now: datetime | None = None) -> list[DkimResult]:
    fields, body = split_message(raw)
    sig_fields = [f for f in fields if f.lname == "dkim-signature"][:MAX_SIGNATURES]
    return [_verify_one(f, fields, body, resolver, now or datetime.now(timezone.utc)) for f in sig_fields]


def _verify_one(sig_field: RawHeader, fields: list[RawHeader], body: bytes, resolver: Resolver | None,
                now: datetime) -> DkimResult:
    res = DkimResult()
    try:
        tags = parse_tags(sig_field.value.decode("utf-8", "replace"))
        for required in ("v", "a", "b", "bh", "d", "h", "s"):
            if required not in tags:
                raise DkimSyntaxError(f"missing required tag {required}=")
        if tags["v"] != "1":
            raise DkimSyntaxError(f"unsupported version v={tags['v']}")
        res.domain, res.selector = tags["d"].lower(), tags["s"]
        res.algorithm = tags["a"].lower()
        if res.algorithm not in _ALGORITHMS:
            raise DkimSyntaxError(f"unsupported algorithm {res.algorithm}")
        res.signed_headers = [h.strip().lower() for h in tags["h"].split(":") if h.strip()]
        if "from" not in res.signed_headers:
            raise DkimSyntaxError("From header is not signed (h= must include from)")
        res.identity = tags.get("i")
        if res.identity and not _is_within(res.identity.rpartition("@")[2].lower(), res.domain):
            raise DkimSyntaxError("i= is not within the d= domain")
        hcanon, _, bcanon = tags.get("c", "simple/simple").lower().partition("/")
        bcanon = bcanon or "simple"
        if hcanon not in ("simple", "relaxed") or bcanon not in ("simple", "relaxed"):
            raise DkimSyntaxError(f"unknown canonicalization c={tags.get('c')}")
        res.canonicalization = f"{hcanon}/{bcanon}"
        if "l" in tags:
            res.body_length_limit = int(tags["l"])
        _set_times(res, tags, now)
        expected_bh = _b64(tags["bh"])
        signature = _b64(tags["b"])
    except (DkimSyntaxError, ValueError) as exc:
        res.result, res.reason = "permerror", f"invalid signature: {exc}"
        return res

    hash_name = _ALGORITHMS[res.algorithm][1]
    cbody = canon_body(body, bcanon)
    if res.body_length_limit is not None:
        cbody = cbody[: res.body_length_limit]
    res.body_hash_ok = hashlib.new(hash_name, cbody).digest() == expected_bh
    if not res.body_hash_ok:
        res.result, res.reason = "fail", "body hash mismatch: the body was changed after signing"
        return res

    data = b"".join(canon_header(f, hcanon) for f in _select_headers(fields, res.signed_headers))
    data += canon_header(_strip_b(sig_field), hcanon).rstrip(b"\r\n")
    if resolver is None:
        res.result, res.reason = "neutral", "body hash matches; signature not checked (offline)"
        return res
    try:
        key = fetch_key(resolver, res.selector, res.domain)
    except KeyError_ as exc:
        res.result, res.reason = exc.result, exc.reason
        return res
    res.key_bits, res.key_testing = key.bits, key.testing
    if key.hashes and hash_name not in key.hashes:
        res.result, res.reason = "permerror", f"key does not allow {hash_name}"
        return res
    if key.strict and res.identity and res.identity.rpartition("@")[2].lower() != res.domain:
        res.result, res.reason = "permerror", "key requires i= domain to equal d= (t=s)"
        return res
    if _verify_signature(key, res.algorithm, data, signature):
        res.result, res.reason = "pass", "signature and body hash verified"
    else:
        res.result, res.reason = "fail", "signature mismatch: signed headers were changed, or the key is different"
    return res


def _is_within(sub: str, domain: str) -> bool:
    return sub == domain or sub.endswith("." + domain)


def _set_times(res: DkimResult, tags: dict[str, str], now: datetime) -> None:
    for tag, attr in (("t", "signed_at"), ("x", "expires_at")):
        if tag in tags:
            try:
                setattr(res, attr, datetime.fromtimestamp(int(tags[tag]), timezone.utc).isoformat())
            except (ValueError, OverflowError, OSError):
                pass
    if "x" in tags:
        try:
            res.expired = int(tags["x"]) < now.timestamp()
        except ValueError:
            pass


# --------------------------------------------------------------------------- ARC


@dataclass
class ArcResult:
    result: str = "none"  # none, pass, fail
    instances: int = 0
    reason: str = ""
    sealers: list[dict] = field(default_factory=list)  # [{"i", "d", "s", "cv"}]


def verify_arc(raw: bytes, resolver: Resolver | None) -> ArcResult:
    fields, body = split_message(raw)
    sets: dict[int, dict[str, RawHeader]] = {}
    out = ArcResult()
    for f in fields:
        kind = {"arc-seal": "as", "arc-message-signature": "ams", "arc-authentication-results": "aar"}.get(f.lname)
        if not kind:
            continue
        m = re.search(r"(?:^|;)\s*i\s*=\s*(\d+)", f.value.decode("utf-8", "replace"))
        if not m:
            out.result, out.reason = "fail", f"{f.name} without a valid i= instance"
            return out
        i = int(m.group(1))
        if kind in sets.setdefault(i, {}):
            out.result, out.reason = "fail", f"duplicate {f.name} for instance {i}"
            return out
        sets[i][kind] = f
    if not sets:
        return out
    n = max(sets)
    out.instances = n
    if n > MAX_ARC_INSTANCES or sorted(sets) != list(range(1, n + 1)):
        out.result, out.reason = "fail", "ARC instances are missing or out of range"
        return out
    seals: dict[int, dict[str, str]] = {}
    try:
        for i in range(1, n + 1):
            if set(sets[i]) != {"as", "ams", "aar"}:
                raise DkimSyntaxError(f"instance {i} is incomplete")
            seals[i] = parse_tags(sets[i]["as"].value.decode("utf-8", "replace"))
            out.sealers.append({"i": i, "d": seals[i].get("d"), "s": seals[i].get("s"), "cv": seals[i].get("cv")})
    except DkimSyntaxError as exc:
        out.result, out.reason = "fail", str(exc)
        return out
    if seals[n].get("cv", "").lower() == "fail":
        out.result, out.reason = "fail", f"instance {n} already recorded a broken chain (cv=fail)"
        return out
    for i in range(1, n + 1):
        expected = "none" if i == 1 else "pass"
        if seals[i].get("cv", "").lower() != expected:
            out.result, out.reason = "fail", f"instance {i} has cv={seals[i].get('cv')} (expected {expected})"
            return out
    if resolver is None:
        out.result, out.reason = "neutral", "structure valid; signatures not checked (offline)"
        return out

    ams = _verify_ams(sets[n]["ams"], fields, body, resolver)
    if ams:
        out.result, out.reason = "fail", f"newest ARC-Message-Signature (i={n}) {ams}"
        return out
    for i in range(n, 0, -1):
        problem = _verify_seal(i, sets, seals[i], resolver)
        if problem:
            out.result, out.reason = "fail", f"ARC-Seal i={i} {problem}"
            return out
    out.result, out.reason = "pass", f"{n} ARC set(s) verified"
    return out


def _verify_ams(ams: RawHeader, fields: list[RawHeader], body: bytes, resolver: Resolver) -> str | None:
    """Return None if valid, else a reason."""
    try:
        tags = parse_tags(ams.value.decode("utf-8", "replace"))
        for required in ("a", "b", "bh", "d", "h", "s"):
            if required not in tags:
                raise DkimSyntaxError(f"missing {required}=")
        algorithm = tags["a"].lower()
        if algorithm not in _ALGORITHMS:
            raise DkimSyntaxError(f"unsupported algorithm {algorithm}")
        hcanon, _, bcanon = tags.get("c", "simple/simple").lower().partition("/")
        bcanon = bcanon or "simple"
        names = [h.strip().lower() for h in tags["h"].split(":") if h.strip()]
        if any(h.startswith("arc-") for h in names):
            raise DkimSyntaxError("h= must not include ARC headers")
        hash_name = _ALGORITHMS[algorithm][1]
        if hashlib.new(hash_name, canon_body(body, bcanon)).digest() != _b64(tags["bh"]):
            return "has a body hash mismatch"
        data = b"".join(canon_header(f, hcanon) for f in _select_headers(fields, names))
        data += canon_header(_strip_b(ams), hcanon).rstrip(b"\r\n")
        key = fetch_key(resolver, tags["s"], tags["d"].lower())
        if not _verify_signature(key, algorithm, data, _b64(tags["b"])):
            return "signature does not verify"
    except DkimSyntaxError as exc:
        return f"is invalid: {exc}"
    except KeyError_ as exc:
        return f"key problem: {exc.reason}"
    return None


def _verify_seal(i: int, sets: dict[int, dict[str, RawHeader]], tags: dict[str, str], resolver: Resolver) -> str | None:
    try:
        algorithm = tags.get("a", "").lower()
        if algorithm not in _ALGORITHMS or not tags.get("d") or not tags.get("s") or not tags.get("b"):
            raise DkimSyntaxError("missing or unsupported a=, d=, s= or b=")
        data = b""
        for j in range(1, i + 1):
            data += canon_header(sets[j]["aar"], "relaxed")
            data += canon_header(sets[j]["ams"], "relaxed")
            if j < i:
                data += canon_header(sets[j]["as"], "relaxed")
        data += canon_header(_strip_b(sets[i]["as"]), "relaxed").rstrip(b"\r\n")
        key = fetch_key(resolver, tags["s"], tags["d"].lower())
        if not _verify_signature(key, algorithm, data, _b64(tags["b"])):
            return "signature does not verify"
    except DkimSyntaxError as exc:
        return f"is invalid: {exc}"
    except KeyError_ as exc:
        return f"key problem: {exc.reason}"
    return None
