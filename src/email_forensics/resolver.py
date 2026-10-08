"""Pluggable DNS resolution for authentication checks and enrichment.

Online lookups are opt-in: they reveal the investigation to the domain owner's DNS
servers, and their answers change over time (DKIM keys rotate, SPF records change).
Every answer is therefore recorded with a timestamp, and a recording can be replayed
later to reproduce a report exactly, offline.

Resolvers:
- ``SystemResolver``  -- dnspython, if installed (``pip install dnspython``)
- ``DohResolver``     -- DNS-over-HTTPS JSON API (stdlib only), e.g. https://dns.google/resolve
- ``ReplayResolver``  -- answers from a recording made earlier (no network)
- ``RecordingResolver`` wraps any of the above and logs every query
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

RECORD_TYPES = ("TXT", "A", "AAAA", "MX", "PTR", "CNAME")
_TYPE_CODES = {"A": 1, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
TIMEOUT = 8.0


class DnsError(Exception):
    """A temporary DNS failure (SERVFAIL, timeout, network)."""


class Resolver:
    name = "resolver"

    def query(self, name: str, rtype: str) -> list[str]:
        """Return answers as strings; [] for NXDOMAIN/NODATA. Raise DnsError on failure.

        TXT answers have their character-strings concatenated; MX answers are
        "preference exchange"; names are returned without the trailing dot.
        """
        raise NotImplementedError


class SystemResolver(Resolver):
    name = "system (dnspython)"

    def __init__(self) -> None:
        try:
            import dns.resolver
        except ImportError as exc:
            raise RuntimeError("dnspython is not installed; use --doh or pip install dnspython") from exc
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = TIMEOUT

    def query(self, name: str, rtype: str) -> list[str]:
        import dns.exception
        import dns.resolver
        try:
            answer = self._resolver.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.DNSException, OSError) as exc:
            raise DnsError(f"{type(exc).__name__}: {exc}") from exc
        out = []
        for rdata in answer:
            if rtype == "TXT":
                out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
            elif rtype == "MX":
                out.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
            else:
                out.append(str(rdata).rstrip("."))
        return out


class DohResolver(Resolver):
    """DNS-over-HTTPS using the JSON API offered by Google and Cloudflare."""

    def __init__(self, url: str = "https://dns.google/resolve") -> None:
        self.url = url
        self.name = f"DoH {url}"

    def query(self, name: str, rtype: str) -> list[str]:
        q = urllib.parse.urlencode({"name": name, "type": rtype})
        req = urllib.request.Request(f"{self.url}?{q}", headers={"accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                data = json.loads(resp.read(1_000_000))
        except (OSError, ValueError) as exc:
            raise DnsError(f"DoH request failed: {exc}") from exc
        status = data.get("Status")
        if status == 3:  # NXDOMAIN
            return []
        if status not in (0, None):
            raise DnsError(f"DNS status {status}")
        code = _TYPE_CODES.get(rtype)
        out = []
        for ans in data.get("Answer", []) or []:
            if ans.get("type") != code:
                continue
            value = str(ans.get("data", ""))
            if rtype == "TXT":
                value = _join_txt(value)
            out.append(value.rstrip("."))
        return out


def _join_txt(value: str) -> str:
    """DoH returns TXT data as '"part1" "part2"' (or unquoted); join the parts."""
    value = value.strip()
    if not value.startswith('"'):
        return value
    parts, cur, in_q, esc = [], [], False, False
    for ch in value:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\" and in_q:
            esc = True
        elif ch == '"':
            if in_q:
                parts.append("".join(cur))
                cur = []
            in_q = not in_q
        elif in_q:
            cur.append(ch)
    return "".join(parts)


class ReplayResolver(Resolver):
    """Answer only from a recording; anything not recorded is reported as missing."""

    def __init__(self, path: str | Path) -> None:
        self.name = f"replay {path}"
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self._answers: dict[tuple[str, str], dict] = {}
        for entry in data.get("lookups", []):
            key = (entry["name"].lower().rstrip("."), entry["type"].upper())
            self._answers[key] = entry

    def query(self, name: str, rtype: str) -> list[str]:
        entry = self._answers.get((name.lower().rstrip("."), rtype.upper()))
        if entry is None:
            raise DnsError(f"{rtype} {name} not in recording")
        if entry.get("error"):
            raise DnsError(entry["error"])
        return list(entry.get("answers", []))


@dataclass
class DnsLookup:
    name: str
    type: str
    answers: list[str] = field(default_factory=list)
    error: str | None = None
    at: str = ""


class RecordingResolver(Resolver):
    """Wraps a resolver, caches answers for this run and records every lookup."""

    def __init__(self, inner: Resolver) -> None:
        self.inner = inner
        self.name = inner.name
        self.lookups: list[DnsLookup] = []
        self._cache: dict[tuple[str, str], DnsLookup] = {}

    def query(self, name: str, rtype: str) -> list[str]:
        key = (name.lower().rstrip("."), rtype.upper())
        hit = self._cache.get(key)
        if hit is None:
            hit = DnsLookup(name=key[0], type=key[1], at=datetime.now(timezone.utc).isoformat())
            try:
                hit.answers = self.inner.query(key[0], key[1])
            except DnsError as exc:
                hit.error = str(exc)
            self._cache[key] = hit
            self.lookups.append(hit)
        if hit.error:
            raise DnsError(hit.error)
        return list(hit.answers)

    def save(self, path: str | Path) -> None:
        data = {"resolver": self.name, "lookups": [vars(lk) for lk in self.lookups]}
        Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
