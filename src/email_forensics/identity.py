"""Sender-identity analysis: lookalike domains, brand/org impersonation in display names,
sending-software fingerprints, provider consistency and provider (Microsoft 365,
SpamAssassin) verdict headers.
"""

from __future__ import annotations

import re
from email.message import EmailMessage

from .brands import BRANDS, FREEMAIL_DOMAINS, PROVIDER_INFRA, PROVIDER_MESSAGE_ID_SUFFIXES
from .domains import domain_of, org_domain
from .headers import parse_addresses, raw_header, raw_headers
from .lookalike import ProtectedDomain, build_protected, check_host
from .mailer import fingerprint
from .models import Attachment, BodyAnalysis, Finding, HeaderAnalysis, IdentityAnalysis, Severity
from .textcheck import safe_display

MAX_URL_HOSTS = 1000

_PHISH_CATEGORIES = {"PHSH", "HPHSH", "HPHISH", "SPOOF", "GIMP", "UIMP", "DIMP", "MALW", "AMP"}
_SPAM_CATEGORIES = {"SPM", "HSPM"}
_BYPASS_VERDICTS = {"SKN", "SKA", "SKI"}
_TRUST_NOTE = "Only trust this if the header was added by your own tenant/gateway."


def analyze_identity(msg: EmailMessage, h: HeaderAnalysis, body: BodyAnalysis,
                     attachments: list[Attachment], extra_protected: list[str] = ()) -> tuple[IdentityAnalysis, list[Finding]]:
    ident = IdentityAnalysis(mailer=h.x_mailer)
    recipients = _recipient_orgs(msg, h)
    ident.recipient_domains = sorted(recipients)
    protected = build_protected(recipients | {d for d in extra_protected if d})
    ident.protected_domain_count = len(protected)

    findings: list[Finding] = []
    findings += _sender_lookalikes(h, protected)
    findings += _url_lookalikes(body, attachments, protected, ident)
    findings += _display_name_impersonation(h, protected)
    findings += _mailer_findings(msg, ident)
    findings += _provider_path_findings(h)
    findings += _provider_verdicts(msg, h, recipients, ident)
    return ident, findings


def _recipient_orgs(msg: EmailMessage, h: HeaderAnalysis) -> set[str]:
    addrs = list(h.to) + list(h.cc)
    for name in ("Delivered-To", "X-Original-To"):
        for value in raw_headers(msg, name, decode=False):
            addrs += [a for _, a in parse_addresses(value) if a]
    return {od for a in addrs if (od := org_domain(domain_of(a.lower()))) and "." in od}


def _sender_lookalikes(h: HeaderAnalysis, protected: list[ProtectedDomain]) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple] = set()
    senders = [("From", h.from_address), ("Return-Path", h.return_path), ("Sender", h.sender)]
    senders += [("Reply-To", r) for r in h.reply_to]
    for location, address in senders:
        for f in check_host(domain_of(address), protected, location):
            key = (f.code, f.evidence.get("host"), f.evidence.get("imitates"))
            if key not in seen:
                seen.add(key)
                out.append(f)
    return out


def _url_lookalikes(body: BodyAnalysis, attachments: list[Attachment], protected: list[ProtectedDomain],
                    ident: IdentityAnalysis) -> list[Finding]:
    hosts: dict[str, None] = {}
    for url in [*body.urls, *(u for a in attachments for u in a.urls)]:
        if url.host and len(hosts) < MAX_URL_HOSTS:
            hosts[url.host] = None
    ident.checked_hosts = len(hosts)
    out: list[Finding] = []
    seen: set[tuple] = set()
    for host in hosts:
        for f in check_host(host, protected, "URL"):
            key = (f.code, org_domain(host), f.evidence.get("imitates"))
            if key not in seen:
                seen.add(key)
                out.append(f)
    return out


def _word_in(word: str, text: str) -> bool:
    # All-caps short names (UPS, IRS, DHL) must match case-sensitively to avoid "ups" in ordinary text.
    flags = 0 if (word.isupper() and len(word) <= 5) else re.I
    return re.search(rf"(?<![\w&]){re.escape(word)}(?![\w&])", text, flags) is not None


def _display_name_impersonation(h: HeaderAnalysis, protected: list[ProtectedDomain]) -> list[Finding]:
    name, addr = h.from_display_name, h.from_address
    from_org = org_domain(domain_of(addr))
    if not name or not from_org:
        return []
    freemail = from_org in FREEMAIL_DOMAINS
    from_label = from_org.split(".", 1)[0]

    for brand, (words, domains) in BRANDS.items():
        word = next((w for w in words if _word_in(w, name)), None)
        if not word:
            continue
        brand_orgs = {org_domain(d) for d in domains}
        # Free-mail addresses (outlook.com, gmail.com) belong to anyone who signs up, so
        # they never count as the brand itself; country domains like amazon.de do.
        if not freemail and (from_org in brand_orgs or from_label in {d.split(".", 1)[0] for d in brand_orgs}):
            return []
        return [Finding(
            "HDR_DISPLAY_NAME_BRAND", Severity.HIGH if freemail else Severity.MEDIUM,
            f"Sender name '{safe_display(name)}' claims to be {word}, but the address is at '{from_org}'"
            f"{' (a free-mail provider)' if freemail else ''}.",
            {"display_name": name, "from": addr, "brand": brand, "freemail": freemail},
        )]

    for p in protected:
        if p.kind != "org" or len(p.label) < 4 or from_org == p.domain:
            continue
        words = {p.label, p.label.replace("-", " ")}
        if any(_word_in(w, name) for w in words):
            return [Finding(
                "HDR_DISPLAY_NAME_ORG", Severity.HIGH if freemail else Severity.MEDIUM,
                f"Sender name '{safe_display(name)}' uses the name of '{p.domain}' but the address is at '{from_org}'.",
                {"display_name": name, "from": addr, "imitates": p.domain, "freemail": freemail},
            )]
    return []


def _mailer_findings(msg: EmailMessage, ident: IdentityAnalysis) -> list[Finding]:
    out: list[Finding] = []
    sig = fingerprint(ident.mailer)
    if sig:
        ident.mailer_name, ident.mailer_category = sig.name, sig.category
        ev = {"mailer": ident.mailer, "fingerprint": sig.name}
        if sig.category == "phishing-kit":
            out.append(Finding("HDR_MAILER_PHISHING_KIT", Severity.HIGH,
                               f"Sent with {sig.name}, a mailer bundled with phishing kits.", ev))
        elif sig.category == "bulk":
            out.append(Finding("HDR_MAILER_BULK", Severity.LOW, f"Sent with mass-mailing software ({sig.name}).", ev))
        elif sig.category == "script":
            out.append(Finding("HDR_MAILER_SCRIPT", Severity.LOW,
                               f"Sent by a script/library ({sig.name}) rather than a mail client. "
                               "Normal for automated mail; unusual for a person writing to you.", ev))
        elif sig.category == "outdated":
            out.append(Finding("HDR_MAILER_OUTDATED", Severity.LOW,
                               f"Mailer claims to be {sig.name}; spam tools often fake long-obsolete clients.", ev))

    php = raw_header(msg, "X-PHP-Originating-Script") or raw_header(msg, "X-PHP-Script")
    if php:
        ident.php_script = php
        out.append(Finding("HDR_PHP_SCRIPT", Severity.MEDIUM,
                           "Sent by a PHP script on a web server (header names the script); "
                           "phishing is often sent from compromised websites.", {"script": php}))
    return out


def _hop_hosts(h: HeaderAnalysis) -> list[str]:
    return [x.lower().rstrip(".") for hop in h.hops for x in (hop.from_host, hop.by_host) if x]


def _on_infra(hosts: list[str], suffixes: tuple[str, ...]) -> bool:
    return any(host == s or host.endswith("." + s) for host in hosts for s in suffixes)


def _provider_path_findings(h: HeaderAnalysis) -> list[Finding]:
    if not h.hops:
        return []  # nothing to compare (e.g. a sent-items copy)
    hosts = _hop_hosts(h)
    out: list[Finding] = []
    from_domain = domain_of(h.from_address)
    for provider, (sender_domains, infra) in PROVIDER_INFRA.items():
        if from_domain in sender_domains and not _on_infra(hosts, infra):
            out.append(Finding("HDR_PROVIDER_PATH_MISMATCH", Severity.MEDIUM,
                               f"From claims a {provider} address ({from_domain}) but no {provider} server "
                               "appears in the delivery path.", {"from": h.from_address, "provider": provider}))

    mid_domain = (h.message_id or "").strip().strip("<>").rpartition("@")[2].lower()
    for provider, suffixes in PROVIDER_MESSAGE_ID_SUFFIXES.items():
        if mid_domain and _on_infra([mid_domain], suffixes) and not _on_infra(hosts, PROVIDER_INFRA[provider][1]):
            out.append(Finding("HDR_MESSAGE_ID_PROVIDER_MISMATCH", Severity.MEDIUM,
                               f"Message-ID looks {provider}-generated ({mid_domain}) but no {provider} "
                               "server appears in the delivery path; the header may be copied or forged.",
                               {"message_id": h.message_id, "provider": provider}))
    return out


def parse_forefront(value: str) -> dict[str, str]:
    """Parse 'CIP:1.2.3.4;CTRY:US;SCL:5;SFV:SPM;CAT:PHSH;...' into a dict."""
    out = {}
    for item in value.split(";"):
        key, sep, val = item.strip().partition(":")
        if sep and key:
            out[key.strip().upper()] = val.strip()
    return out


def _int(value: str | None) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _provider_verdicts(msg: EmailMessage, h: HeaderAnalysis, recipients: set[str],
                       ident: IdentityAnalysis) -> list[Finding]:
    out: list[Finding] = []
    ms: dict[str, str] = {}
    forefront = raw_header(msg, "X-Forefront-Antispam-Report")
    if forefront:
        parsed = parse_forefront(forefront)
        ms.update({k: v for k, v in parsed.items() if k in ("SCL", "SFV", "CAT", "CIP", "CTRY", "PTR", "DIR", "IPV")})
    for header, key in (("X-MS-Exchange-Organization-SCL", "SCL"),
                        ("X-MS-Exchange-Organization-AuthAs", "AuthAs")):
        value = raw_header(msg, header)
        if value:
            ms.setdefault(key, value.strip())
    antispam = raw_header(msg, "X-Microsoft-Antispam")
    if antispam and "BCL" in (parsed_as := parse_forefront(antispam)):
        ms["BCL"] = parsed_as["BCL"]

    if ms:
        ident.provider_verdicts["microsoft365"] = ms
        ev = {"provider": "Microsoft 365", **ms}
        cat, sfv = ms.get("CAT", "").upper(), ms.get("SFV", "").upper()
        scl, bcl = _int(ms.get("SCL")), _int(ms.get("BCL"))
        if cat in _PHISH_CATEGORIES:
            out.append(Finding("PROVIDER_PHISH_VERDICT", Severity.HIGH,
                               f"Microsoft 365 classified this message as {cat} (phishing/spoofing/malware). {_TRUST_NOTE}", ev))
        elif cat in _SPAM_CATEGORIES or sfv == "SPM" or (scl is not None and scl >= 5):
            out.append(Finding("PROVIDER_SPAM_VERDICT", Severity.MEDIUM,
                               f"Microsoft 365 classified this message as spam (SCL {ms.get('SCL', '?')}). {_TRUST_NOTE}", ev))
        elif cat == "BULK" or (bcl is not None and bcl >= 7):
            out.append(Finding("PROVIDER_BULK_VERDICT", Severity.LOW,
                               f"Microsoft 365 classified this message as bulk mail (BCL {ms.get('BCL', '?')}).", ev))
        if sfv in _BYPASS_VERDICTS or scl == -1:
            out.append(Finding("PROVIDER_FILTER_BYPASSED", Severity.INFO,
                               "Spam filtering was skipped by an allow list or mail-flow rule (SCL -1 / SFV:SK*). "
                               "Check the rule if the message is malicious.", ev))
        from_org = org_domain(domain_of(h.from_address))
        if ms.get("AuthAs", "").lower() == "anonymous" and from_org in recipients:
            out.append(Finding("PROVIDER_EXTERNAL_CLAIMS_INTERNAL", Severity.HIGH,
                               f"Message arrived unauthenticated from outside, yet claims an internal sender ({from_org}). "
                               f"{_TRUST_NOTE}", ev))

    spam_status = raw_header(msg, "X-Spam-Status")
    spam_flag = raw_header(msg, "X-Spam-Flag")
    if spam_status or spam_flag:
        sa = {k: v for k, v in (("status", spam_status), ("flag", spam_flag)) if v}
        m = re.search(r"score=(-?[\d.]+)", spam_status or "")
        if m:
            sa["score"] = m.group(1)
        ident.provider_verdicts["spamassassin"] = sa
        if (spam_status or "").lower().startswith("yes") or (spam_flag or "").strip().lower() == "yes":
            out.append(Finding("PROVIDER_SPAM_VERDICT", Severity.MEDIUM,
                               f"SpamAssassin marked this message as spam (score {sa.get('score', '?')}). {_TRUST_NOTE}",
                               {"provider": "SpamAssassin", **sa}))
    return out
