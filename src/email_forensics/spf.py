"""SPF evaluation (RFC 7208) against a pluggable resolver.

Forensic caveat: this evaluates the sender's *current* SPF record. If the record
changed since the message was delivered, the result can differ from the receiver's.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .resolver import DnsError, Resolver

MAX_DNS_LOOKUPS = 10
MAX_VOID_LOOKUPS = 2
MAX_MX = 10
_QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


@dataclass
class SpfResult:
    result: str = "none"  # pass, fail, softfail, neutral, none, permerror, temperror
    ip: str | None = None
    domain: str | None = None  # domain whose policy was evaluated (MAIL FROM or HELO)
    identity: str | None = None  # "mailfrom" or "helo"
    mechanism: str | None = None  # the term that matched
    record: str | None = None
    reason: str = ""
    lookups: int = 0
    trace: list[str] = field(default_factory=list)


class _PermError(Exception):
    pass


class _TempError(Exception):
    pass


class _Evaluator:
    def __init__(self, resolver: Resolver, ip: str, sender: str, helo: str | None) -> None:
        self.resolver = resolver
        self.ip = ipaddress.ip_address(ip)
        self.sender = sender
        self.helo = helo or ""
        self.lookups = 0
        self.voids = 0
        self.trace: list[str] = []

    # -- DNS helpers ---------------------------------------------------------------
    def _count(self) -> None:
        self.lookups += 1
        if self.lookups > MAX_DNS_LOOKUPS:
            raise _PermError(f"more than {MAX_DNS_LOOKUPS} DNS-querying terms")

    def _query(self, name: str, rtype: str, void_counts: bool = True) -> list[str]:
        try:
            answers = self.resolver.query(name, rtype)
        except DnsError as exc:
            raise _TempError(str(exc)) from exc
        if not answers and void_counts:
            self.voids += 1
            if self.voids > MAX_VOID_LOOKUPS:
                raise _PermError(f"more than {MAX_VOID_LOOKUPS} void lookups")
        return answers

    def _addresses(self, name: str) -> list[ipaddress._BaseAddress]:
        rtype = "A" if self.ip.version == 4 else "AAAA"
        out = []
        for a in self._query(name, rtype):
            try:
                out.append(ipaddress.ip_address(a))
            except ValueError:
                continue
        return out

    def _in(self, addr, cidr4: int, cidr6: int) -> bool:
        if addr.version != self.ip.version:
            return False
        prefix = cidr4 if addr.version == 4 else cidr6
        return self.ip in ipaddress.ip_network(f"{addr}/{prefix}", strict=False)

    # -- record & macros -------------------------------------------------------------
    def record(self, domain: str) -> str | None:
        try:
            txts = self.resolver.query(domain, "TXT")
        except DnsError as exc:
            raise _TempError(str(exc)) from exc
        spf = [t for t in txts if re.match(r"^v=spf1(\s|$)", t, re.I)]
        if len(spf) > 1:
            raise _PermError(f"{domain} publishes {len(spf)} SPF records")
        return spf[0] if spf else None

    def expand(self, spec: str, domain: str) -> str:
        local, _, sdomain = self.sender.rpartition("@")
        local = local or "postmaster"

        def macro(m: re.Match) -> str:
            letter, digits, reverse, delims = m.group(1).lower(), m.group(2), m.group(3), m.group(4) or "."
            if letter == "s":
                value = self.sender
            elif letter == "l":
                value = local
            elif letter == "o":
                value = sdomain
            elif letter == "d":
                value = domain
            elif letter == "i":
                value = (".".join(self.ip.exploded.replace(":", "")) if self.ip.version == 6 else str(self.ip))
            elif letter == "v":
                value = "in-addr" if self.ip.version == 4 else "ip6"
            elif letter == "h":
                value = self.helo
            else:
                raise _PermError(f"unsupported macro letter {letter!r}")
            parts = re.split("[" + re.escape(delims) + "]", value)
            if reverse:
                parts.reverse()
            if digits:
                n = int(digits)
                if n == 0:
                    raise _PermError("macro digit transformer of 0")
                parts = parts[-n:]
            return ".".join(parts)

        out, pos = [], 0
        for m in re.finditer(r"%(?:\{([slodiphcrtv])(\d*)(r?)([.\-+,/_=]*)\}|(%)|(_)|(-))", spec, re.I):
            out.append(spec[pos:m.start()])
            if m.group(5):
                out.append("%")
            elif m.group(6):
                out.append(" ")
            elif m.group(7):
                out.append("%20")
            else:
                out.append(macro(m))
            pos = m.end()
        rest = spec[pos:]
        if "%" in rest:
            raise _PermError(f"invalid macro in {spec!r}")
        out.append(rest)
        return "".join(out).rstrip(".")

    # -- evaluation -------------------------------------------------------------------
    def check_host(self, domain: str, depth: int = 0) -> tuple[str, str | None, str | None]:
        """Return (result, matched term, record)."""
        if depth > MAX_DNS_LOOKUPS:
            raise _PermError("include/redirect loop")
        record = self.record(domain)
        if record is None:
            return "none", None, None
        self.trace.append(f"{domain}: {record}")
        terms = record.split()[1:]
        redirect = None
        for term in terms:
            m = re.fullmatch(r"([a-zA-Z][\w.-]*)=(.*)", term)
            if m:
                name = m.group(1).lower()
                if name == "redirect":
                    if redirect is not None:
                        raise _PermError("duplicate redirect=")
                    redirect = m.group(2)
                elif name == "exp":
                    continue
                continue
            qualifier = "+"
            if term[0] in _QUALIFIERS:
                qualifier, term = term[0], term[1:]
            if self._matches(term, domain, depth):
                return _QUALIFIERS[qualifier], qualifier + term, record
        if redirect is not None:
            self._count()
            target = self.expand(redirect, domain)
            result, matched, _ = self.check_host(target, depth + 1)
            if result == "none":
                raise _PermError(f"redirect target {target} has no SPF record")
            return result, matched, record
        return "neutral", None, record

    def _matches(self, term: str, domain: str, depth: int) -> bool:
        m = re.fullmatch(r"(all|include|a|mx|ptr|ip4|ip6|exists)(?::([^/]*))?(?:/(\d+))?(?://(\d+))?", term, re.I)
        if not m:
            raise _PermError(f"unknown mechanism {term!r}")
        mech, arg, c4, c6 = m.group(1).lower(), m.group(2), m.group(3), m.group(4)
        cidr4 = int(c4) if c4 else 32
        cidr6 = int(c6) if c6 else 128
        if mech in ("ip4", "ip6") and arg:
            prefix = c4
            try:
                net = ipaddress.ip_network(f"{arg}/{prefix}" if prefix else arg, strict=False)
            except ValueError as exc:
                raise _PermError(f"bad network in {term!r}") from exc
            return net.version == self.ip.version and self.ip in net
        if mech == "all":
            return True
        if cidr4 > 32 or cidr6 > 128:
            raise _PermError(f"bad CIDR length in {term!r}")
        target = self.expand(arg, domain) if arg else domain
        if mech == "include":
            if not arg:
                raise _PermError("include without domain")
            self._count()
            result, _, _ = self.check_host(target, depth + 1)
            if result == "pass":
                return True
            if result in ("fail", "softfail", "neutral"):
                return False
            if result == "temperror":
                raise _TempError(f"include:{target} temperror")
            raise _PermError(f"include:{target} returned {result}")
        if mech == "a":
            self._count()
            return any(self._in(a, cidr4, cidr6) for a in self._addresses(target))
        if mech == "mx":
            self._count()
            exchanges = [mx.split()[-1] for mx in self._query(target, "MX")]
            if len(exchanges) > MAX_MX:
                raise _PermError("too many MX records")
            return any(self._in(a, cidr4, cidr6) for ex in exchanges for a in self._addresses(ex))
        if mech == "exists":
            self._count()
            return bool(self._query(target, "A"))
        if mech == "ptr":
            self._count()
            rev = ipaddress.ip_address(self.ip).reverse_pointer
            for name in self._query(rev, "PTR", void_counts=False)[:MAX_MX]:
                if (name == target or name.endswith("." + target)) and self.ip in self._addresses(name):
                    return True
            return False
        raise _PermError(f"unsupported mechanism {term!r}")


def check_spf(resolver: Resolver, ip: str, mail_from: str | None, helo: str | None = None) -> SpfResult:
    """Evaluate SPF for `ip`. Uses the MAIL FROM domain, or HELO when MAIL FROM is empty (bounces)."""
    res = SpfResult(ip=ip)
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        res.result, res.reason = "permerror", f"invalid IP {ip!r}"
        return res
    if mail_from and "@" in mail_from:
        sender, domain, res.identity = mail_from, mail_from.rpartition("@")[2].lower(), "mailfrom"
    elif helo:
        sender, domain, res.identity = f"postmaster@{helo}", helo.lower(), "helo"
    else:
        res.result, res.reason = "none", "no MAIL FROM or HELO domain to check"
        return res
    res.domain = domain
    ev = _Evaluator(resolver, ip, sender, helo)
    try:
        res.result, res.mechanism, res.record = ev.check_host(domain)
        res.reason = (f"matched {res.mechanism}" if res.mechanism else
                      "no SPF record" if res.result == "none" else "no mechanism matched")
    except _PermError as exc:
        res.result, res.reason = "permerror", str(exc)
    except _TempError as exc:
        res.result, res.reason = "temperror", str(exc)
    res.lookups, res.trace = ev.lookups, ev.trace
    return res
