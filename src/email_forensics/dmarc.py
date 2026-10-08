"""DMARC (RFC 7489) policy discovery and alignment."""

from __future__ import annotations

from dataclasses import dataclass, field

from .domains import org_domain
from .resolver import DnsError, Resolver


@dataclass
class DmarcResult:
    result: str = "none"  # pass, fail, none (no policy), temperror, permerror
    from_domain: str | None = None
    policy_domain: str | None = None
    record: str | None = None
    policy: str | None = None  # none / quarantine / reject that applies to this From domain
    pct: int = 100
    adkim: str = "r"
    aspf: str = "r"
    dkim_aligned: list[str] = field(default_factory=list)
    spf_aligned: bool = False
    reason: str = ""


def _aligned(domain: str | None, from_domain: str, mode: str) -> bool:
    if not domain:
        return False
    domain = domain.lower().rstrip(".")
    if mode == "s":
        return domain == from_domain
    return org_domain(domain) == org_domain(from_domain)


def _fetch(resolver: Resolver, domain: str) -> str | None:
    records = [r for r in resolver.query(f"_dmarc.{domain}", "TXT") if r.strip().lower().startswith("v=dmarc1")]
    if len(records) > 1:
        raise ValueError(f"{len(records)} DMARC records at _dmarc.{domain}")
    return records[0] if records else None


def _tags(record: str) -> dict[str, str]:
    out = {}
    for item in record.split(";"):
        k, sep, v = item.partition("=")
        if sep:
            out[k.strip().lower()] = v.strip()
    return out


def check_dmarc(resolver: Resolver, from_domain: str | None, dkim_pass_domains: list[str],
                spf_result: str | None, spf_domain: str | None) -> DmarcResult:
    res = DmarcResult(from_domain=from_domain)
    if not from_domain:
        res.result, res.reason = "permerror", "no usable From domain"
        return res
    from_domain = from_domain.lower().rstrip(".")
    org = org_domain(from_domain) or from_domain
    try:
        record, res.policy_domain = _fetch(resolver, from_domain), from_domain
        if record is None and org != from_domain:
            record, res.policy_domain = _fetch(resolver, org), org
    except DnsError as exc:
        res.result, res.reason = "temperror", f"DMARC lookup failed: {exc}"
        return res
    except ValueError as exc:
        res.result, res.reason = "permerror", str(exc)
        return res
    if record is None:
        res.policy_domain = None
        res.result, res.reason = "none", f"no DMARC policy for {from_domain} or {org}"
        return res

    res.record = record
    tags = _tags(record)
    p = tags.get("p", "").lower()
    if p not in ("none", "quarantine", "reject"):
        res.result, res.reason = "permerror", f"invalid or missing p= in {record!r}"
        return res
    sp = tags.get("sp", "").lower()
    res.policy = sp if (res.policy_domain != from_domain and sp in ("none", "quarantine", "reject")) else p
    res.adkim = "s" if tags.get("adkim", "r").lower() == "s" else "r"
    res.aspf = "s" if tags.get("aspf", "r").lower() == "s" else "r"
    try:
        res.pct = max(0, min(100, int(tags.get("pct", "100"))))
    except ValueError:
        res.pct = 100

    res.dkim_aligned = sorted({d for d in dkim_pass_domains if _aligned(d, from_domain, res.adkim)})
    res.spf_aligned = spf_result == "pass" and _aligned(spf_domain, from_domain, res.aspf)
    if res.dkim_aligned or res.spf_aligned:
        how = ", ".join(([f"DKIM d={d}" for d in res.dkim_aligned]) + (["SPF"] if res.spf_aligned else []))
        res.result, res.reason = "pass", f"aligned via {how}"
    else:
        res.result = "fail"
        res.reason = (f"no aligned DKIM pass or SPF pass for {from_domain} "
                      f"(policy {res.policy}{'' if res.pct == 100 else f', pct={res.pct}'})")
    return res
