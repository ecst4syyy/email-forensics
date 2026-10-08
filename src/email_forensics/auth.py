"""Re-verification of email authentication (DKIM, SPF, DMARC, ARC).

Offline (default): DKIM body hashes and signature syntax, ARC chain structure.
Online (opt-in, with a resolver): DKIM/ARC signatures, SPF and DMARC, compared
with what the receiving server recorded in Authentication-Results.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from email.message import EmailMessage

from .dkimcheck import ArcResult, DkimResult, canon_body, split_message, verify_arc, verify_dkim
from .dmarc import DmarcResult, check_dmarc
from .domains import domain_of, org_domain
from .headers import raw_header, raw_headers
from .models import Finding, HeaderAnalysis, Severity
from .resolver import DnsLookup, RecordingResolver
from .spf import SpfResult, check_spf

_SPF_SEVERITY = {"fail": Severity.HIGH, "softfail": Severity.MEDIUM, "neutral": Severity.LOW,
                 "none": Severity.LOW, "permerror": Severity.LOW, "temperror": Severity.LOW}
_TIME_NOTE = "DNS answers reflect today, not delivery time."


@dataclass
class AuthVerification:
    online: bool = False
    resolver: str | None = None
    reconstructed: bool = False
    dkim: list[DkimResult] = field(default_factory=list)
    arc: ArcResult | None = None
    spf: SpfResult | None = None
    spf_ip_source: str | None = None
    dmarc: DmarcResult | None = None
    dns_lookups: list[DnsLookup] = field(default_factory=list)


def verify_authentication(raw: bytes, msg: EmailMessage, h: HeaderAnalysis,
                          resolver: RecordingResolver | None = None, spf_ip: str | None = None,
                          reconstructed: bool = False) -> tuple[AuthVerification, list[Finding]]:
    """`reconstructed`: the MIME was rebuilt (.msg) or re-serialised (attached message), so
    DKIM failures are expected and must not be reported as tampering."""
    av = AuthVerification(online=resolver is not None, resolver=resolver.name if resolver else None,
                          reconstructed=reconstructed)
    findings: list[Finding] = []

    av.dkim = verify_dkim(raw, resolver)
    if reconstructed:
        findings += _reconstructed_dkim_findings(av.dkim)
    else:
        findings += _dkim_findings(av.dkim, raw, online=resolver is not None)
    arc = verify_arc(raw, resolver)
    if arc.instances:
        av.arc = arc
        findings += _arc_findings(arc)

    if resolver is None:
        if av.dkim or av.arc:
            findings.append(Finding("AUTHV_OFFLINE", Severity.INFO,
                                    "Signatures were not verified against DNS (offline). Use --online, --doh or "
                                    "--dns-replay to verify DKIM/ARC signatures, SPF and DMARC."))
        return av, findings

    ip, source, mail_from, helo = spf_inputs(msg, h, spf_ip)
    av.spf_ip_source = source
    if ip:
        av.spf = check_spf(resolver, ip, mail_from, helo)
        findings += _spf_findings(av.spf, source)
    else:
        findings.append(Finding("AUTHV_SPF_NO_IP", Severity.INFO,
                                "Could not determine the connecting IP for SPF; pass --spf-ip to set it."))

    dkim_pass = [r.domain for r in av.dkim if r.result == "pass" and r.domain]
    from_domain = domain_of(h.from_address)
    av.dmarc = check_dmarc(resolver, from_domain, dkim_pass,
                           av.spf.result if av.spf else None, av.spf.domain if av.spf else None)
    findings += _dmarc_findings(av.dmarc)
    if not reconstructed:
        findings += _compare_with_receiver(h, av)
    av.dns_lookups = list(resolver.lookups)
    if any(lk.error for lk in resolver.lookups):
        errors = [f"{lk.type} {lk.name}: {lk.error}" for lk in resolver.lookups if lk.error]
        findings.append(Finding("AUTHV_DNS_ERRORS", Severity.LOW,
                                f"{len(errors)} DNS lookup(s) failed; affected results are temperror.",
                                {"errors": errors[:10]}))
    return av, findings


# --------------------------------------------------------------------------- SPF inputs


def _kv(text: str) -> dict[str, str]:
    return {k.lower(): v.strip('"') for k, v in re.findall(r"([\w.-]+)=(\"[^\"]*\"|[^;\s]+)", text)}


def _valid_ip(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address((value or "").strip("[]")))
    except ValueError:
        return None


def spf_inputs(msg: EmailMessage, h: HeaderAnalysis, override: str | None = None
               ) -> tuple[str | None, str | None, str | None, str | None]:
    """Return (ip, where the IP came from, MAIL FROM, HELO)."""
    received_spf = raw_header(msg, "Received-SPF") or ""
    kv = _kv(received_spf)
    mail_from = kv.get("envelope-from") or None
    helo = kv.get("helo") or None
    for r in h.auth_results:
        if r.method == "spf" and not mail_from:
            mail_from = r.properties.get("smtp.mailfrom")
    if mail_from and "@" not in mail_from:
        mail_from = f"postmaster@{mail_from}"
    mail_from = mail_from or h.return_path

    if override:
        return _valid_ip(override), "--spf-ip", mail_from, helo
    if ip := _valid_ip(kv.get("client-ip")):
        return ip, "Received-SPF client-ip", mail_from, helo
    for value in raw_headers(msg, "Authentication-Results", decode=False):
        m = re.search(r"designates ([0-9a-fA-F:.]+) as permitted sender|sender IP is ([0-9a-fA-F:.]+)", value)
        if m and (ip := _valid_ip(m.group(1) or m.group(2))):
            return ip, "Authentication-Results comment", mail_from, helo
    # Newest hop that crosses an organisational boundary from a public IP.
    for hop in reversed(h.hops):
        if hop.from_ip and hop.ip_is_private is False:
            crosses = org_domain(hop.from_host or "") != org_domain(hop.by_host or "")
            if crosses or hop is h.hops[0]:
                return hop.from_ip, f"Received hop {hop.index} (heuristic)", mail_from, helo or hop.from_host
    return None, None, mail_from, helo


# --------------------------------------------------------------------------- findings


def _dkim_findings(results: list[DkimResult], raw: bytes, online: bool) -> list[Finding]:
    out: list[Finding] = []
    if not results:
        out.append(Finding("AUTHV_NO_DKIM", Severity.INFO, "The message carries no DKIM signature."))
        return out
    _, body = split_message(raw)
    for r in results:
        ev = {"domain": r.domain, "selector": r.selector, "algorithm": r.algorithm, "reason": r.reason}
        label = f"DKIM signature d={r.domain} s={r.selector}"
        if r.body_hash_ok is False:
            out.append(Finding("AUTHV_DKIM_BODY_MODIFIED", Severity.HIGH,
                               f"{label}: the body no longer matches the signed body hash; it was modified "
                               "after signing (by a forwarder/list footer, or tampering).", ev))
        elif r.result == "permerror" and not online:
            out.append(Finding("AUTHV_DKIM_INVALID", Severity.LOW, f"{label} is malformed: {r.reason}.", ev))
        elif r.result == "pass":
            out.append(Finding("AUTHV_DKIM_PASS", Severity.INFO, f"{label} verified.", ev))
        elif r.result == "fail":
            out.append(Finding("AUTHV_DKIM_FAIL", Severity.HIGH,
                               f"{label} does not verify: {r.reason}. {_TIME_NOTE}", ev))
        elif r.result == "permerror":
            sev = Severity.MEDIUM if "no key" in r.reason or "revoked" in r.reason else Severity.LOW
            out.append(Finding("AUTHV_DKIM_PERMERROR", sev, f"{label}: {r.reason}.", ev))
        elif r.result == "temperror":
            out.append(Finding("AUTHV_DKIM_TEMPERROR", Severity.LOW, f"{label}: {r.reason}.", ev))

        if r.body_length_limit is not None and r.body_hash_ok:
            full = len(canon_body(body, (r.canonicalization or "simple/simple").split("/")[1]))
            if full > r.body_length_limit:
                out.append(Finding("AUTHV_DKIM_UNSIGNED_CONTENT", Severity.HIGH,
                                   f"{label} covers only the first {r.body_length_limit} of {full} body bytes "
                                   "(l= tag); the rest was added after signing and is not authenticated.",
                                   {**ev, "signed_bytes": r.body_length_limit, "body_bytes": full}))
            else:
                out.append(Finding("AUTHV_DKIM_LENGTH_TAG", Severity.LOW,
                                   f"{label} uses the l= body length tag, which lets anyone append content.", ev))
        if r.result == "pass":
            if r.key_bits and r.algorithm.startswith("rsa") and r.key_bits < 1024:
                out.append(Finding("AUTHV_DKIM_WEAK_KEY", Severity.MEDIUM,
                                   f"{label} uses a {r.key_bits}-bit RSA key, which can be forged.", ev))
            elif r.key_bits and r.algorithm.startswith("rsa") and r.key_bits < 2048:
                out.append(Finding("AUTHV_DKIM_WEAK_KEY", Severity.LOW, f"{label} uses a {r.key_bits}-bit RSA key.", ev))
            if r.algorithm == "rsa-sha1":
                out.append(Finding("AUTHV_DKIM_SHA1", Severity.LOW, f"{label} uses the deprecated rsa-sha1.", ev))
            if r.key_testing:
                out.append(Finding("AUTHV_DKIM_TESTING", Severity.LOW,
                                   f"{label}: the key is flagged as testing (t=y); receivers may ignore it.", ev))
        if r.expired:
            out.append(Finding("AUTHV_DKIM_EXPIRED", Severity.INFO,
                               f"{label} has passed its x= expiry ({r.expires_at}); normal for old evidence.", ev))
    return out


def _reconstructed_dkim_findings(results: list[DkimResult]) -> list[Finding]:
    passed = [r for r in results if r.result == "pass"]
    out = [Finding("AUTHV_DKIM_PASS", Severity.INFO, f"DKIM signature d={r.domain} s={r.selector} verified.",
                   {"domain": r.domain, "selector": r.selector}) for r in passed]
    if len(passed) < len(results):
        out.append(Finding("AUTHV_DKIM_UNVERIFIABLE", Severity.INFO,
                           "The analysed MIME was rebuilt from an Outlook .msg or re-serialised from a parent "
                           "message, so DKIM signatures that do not verify say nothing about tampering. "
                           "Obtain the original .eml from the mail server to verify them.",
                           {"signatures": [f"d={r.domain} s={r.selector}: {r.result}" for r in results]}))
    return out


def _arc_findings(arc: ArcResult) -> list[Finding]:
    ev = {"instances": arc.instances, "sealers": arc.sealers, "reason": arc.reason}
    if arc.result == "fail":
        return [Finding("AUTHV_ARC_FAIL", Severity.MEDIUM, f"ARC chain is broken: {arc.reason}.", ev)]
    if arc.result == "pass":
        sealers = ", ".join(s["d"] or "?" for s in arc.sealers)
        return [Finding("AUTHV_ARC_PASS", Severity.INFO, f"ARC chain of {arc.instances} verified (sealed by {sealers}).", ev)]
    return []


def _spf_findings(spf: SpfResult, source: str | None) -> list[Finding]:
    ev = {"ip": spf.ip, "ip_source": source, "domain": spf.domain, "identity": spf.identity,
          "mechanism": spf.mechanism, "record": spf.record, "reason": spf.reason}
    if spf.result == "pass":
        return [Finding("AUTHV_SPF_PASS", Severity.INFO, f"SPF pass: {spf.ip} is allowed to send for {spf.domain}.", ev)]
    return [Finding(f"AUTHV_SPF_{spf.result.upper()}", _SPF_SEVERITY.get(spf.result, Severity.LOW),
                    f"SPF {spf.result} for {spf.ip} sending as {spf.domain or '?'} ({spf.reason}; IP from {source}). "
                    f"{_TIME_NOTE}", ev)]


def _dmarc_findings(d: DmarcResult) -> list[Finding]:
    ev = {"from_domain": d.from_domain, "policy_domain": d.policy_domain, "policy": d.policy,
          "record": d.record, "reason": d.reason}
    if d.result == "pass":
        out = [Finding("AUTHV_DMARC_PASS", Severity.INFO, f"DMARC pass ({d.reason}).", ev)]
    elif d.result == "fail":
        sev = Severity.HIGH if d.policy in ("quarantine", "reject") else Severity.MEDIUM
        out = [Finding("AUTHV_DMARC_FAIL", sev,
                       f"DMARC fail for {d.from_domain}: {d.reason}. The From domain is not authenticated.", ev)]
    elif d.result == "none":
        out = [Finding("AUTHV_DMARC_NONE", Severity.LOW,
                       f"{d.from_domain} publishes no DMARC policy, so spoofing it is not blocked.", ev)]
    else:
        out = [Finding(f"AUTHV_DMARC_{d.result.upper()}", Severity.LOW, f"DMARC {d.result}: {d.reason}.", ev)]
    if d.result in ("pass", "fail") and d.policy == "none":
        out.append(Finding("AUTHV_DMARC_POLICY_NONE", Severity.LOW,
                           f"{d.policy_domain} uses p=none (monitoring only): failing mail is still delivered.", ev))
    return out


def _compare_with_receiver(h: HeaderAnalysis, av: AuthVerification) -> list[Finding]:
    """Compare with the top-most Authentication-Results (the final receiver's)."""
    if not h.auth_results:
        return []
    top = h.auth_results[0].authserv_id
    reported = [r for r in h.auth_results if r.authserv_id == top]
    out = []
    for r in reported:
        if r.method == "dkim":
            d = (r.properties.get("header.d") or r.properties.get("header.i", "").lstrip("@").rpartition("@")[2]).lower()
            ours = [x for x in av.dkim if x.domain and (not d or x.domain == d)]
            if r.result == "pass" and ours and all(x.result == "fail" for x in ours):
                out.append(Finding("AUTHV_MISMATCH", Severity.HIGH,
                                   f"{top} recorded dkim=pass for {d or 'the message'}, but it fails now. "
                                   "The message was altered after delivery, or the signing key was replaced.",
                                   {"method": "dkim", "domain": d, "reported": r.result,
                                    "now": [x.result for x in ours], "reasons": [x.reason for x in ours]}))
        elif r.method in ("spf", "dmarc"):
            now = av.spf.result if r.method == "spf" and av.spf else av.dmarc.result if r.method == "dmarc" and av.dmarc else None
            if now and now not in ("temperror",) and r.result != now and {r.result, now} & {"pass"}:
                out.append(Finding("AUTHV_MISMATCH", Severity.MEDIUM,
                                   f"{top} recorded {r.method}={r.result} at delivery; re-checking today gives {now}. "
                                   "DNS records may have changed, or the reported result was forged.",
                                   {"method": r.method, "reported": r.result, "now": now}))
    return out

