"""Lookalike-domain detection: homoglyphs, typos, combosquatting, brand-in-subdomain, mixed scripts.

A domain is compared with a list of *protected* domains (impersonated brands plus the
organisation's own and partner domains). Only near-misses are reported; a domain that
belongs to a protected organisation is never flagged against the others.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

from .brands import BRANDS, COMBO_KEYWORDS, GENERIC_BRAND_LABELS
from .domains import org_domain
from .models import Finding, Severity

# Single characters that render like a Latin letter or digit (a practical subset of
# Unicode TR39 confusables, plus common ASCII substitutions).
_CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "l",
    "ї": "l", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ӏ": "l", "ԛ": "q", "ԝ": "w", "к": "k",
    "ү": "y", "в": "b", "м": "m", "т": "t", "н": "h", "г": "r",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "υ": "u", "ι": "l", "κ": "k", "τ": "t", "χ": "x",
    "ε": "e", "ω": "w", "β": "b",
    # Armenian
    "օ": "o", "ս": "u", "ց": "g", "հ": "h", "ո": "n",
    # Latin look-alikes and ASCII substitutions
    "ı": "l", "ł": "l", "ƚ": "l", "ɡ": "g", "ɑ": "a", "ʀ": "r", "ᴠ": "v", "ß": "b",
    "0": "o", "1": "l", "i": "l", "|": "l", "3": "e", "5": "s", "$": "s", "@": "a",
}
_MULTI = (("rn", "m"), ("vv", "w"))
# Scripts whose letters are routinely confused with Latin ones.
_CONFUSABLE_SCRIPTS = {"CYRILLIC", "GREEK", "ARMENIAN"}
_JAPANESE = {"CJK", "HIRAGANA", "KATAKANA"}


@dataclass(frozen=True)
class ProtectedDomain:
    domain: str  # organisational domain, e.g. "paypal.com"
    kind: str  # "brand" or "org" (the recipient's or a user-configured domain)
    brand: str | None = None

    @property
    def label(self) -> str:
        return self.domain.split(".", 1)[0]

    @property
    def suffix(self) -> str:
        return self.domain.split(".", 1)[1] if "." in self.domain else ""


def build_protected(org_domains: list[str] | set[str] = ()) -> list[ProtectedDomain]:
    """Brand domains plus organisation domains (which take precedence)."""
    out: dict[str, ProtectedDomain] = {}
    for brand, (_, domains) in BRANDS.items():
        for d in domains:
            out[d] = ProtectedDomain(d, "brand", brand)
    for d in org_domains:
        od = org_domain(d.strip().lower().rstrip("."))
        if od and "." in od:
            out[od] = ProtectedDomain(od, "org")
    return list(out.values())


def decode_idna(host: str) -> str:
    """Decode punycode labels (xn--) to Unicode; undecodable labels are kept as-is."""
    labels = []
    for label in host.lower().rstrip(".").split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


@lru_cache(maxsize=65536)
def skeleton(text: str) -> str:
    """Map a label to a canonical form in which visually confusable strings are equal."""
    text = unicodedata.normalize("NFKD", text.lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = "".join(_CONFUSABLES.get(ch, ch) for ch in text)
    text = text.replace("-", "").replace("_", "")
    for seq, repl in _MULTI:
        text = text.replace(seq, repl)
    return text


def scripts(label: str) -> set[str]:
    found = set()
    for ch in label:
        if not ch.isalpha():
            continue
        name = unicodedata.name(ch, "")
        script = name.split(" ", 1)[0] if name else "UNKNOWN"
        found.add("JAPANESE" if script in _JAPANESE else script)
    return found


def edit_distance(a: str, b: str, limit: int) -> int:
    """Optimal-string-alignment distance (Levenshtein + adjacent transpositions), capped at limit+1."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[-_.]", text) if t]


def _is_combo(label: str, p: ProtectedDomain) -> bool:
    """'paypal-secure', 'securepaypal', 'acme-invoices' (org). Brands need a phishing keyword,
    since many brand names are ordinary words ('office-supplies')."""
    if p.label not in label:  # every combo form contains the name; cheap early exit
        return False
    if re.search(rf"(?:^|[-_]){re.escape(p.label)}(?:[-_]|$)", label):
        rest = _tokens(label.replace(p.label, "", 1))
        return p.kind == "org" or bool(set(rest) & COMBO_KEYWORDS)
    if label.startswith(p.label):
        return label[len(p.label):] in COMBO_KEYWORDS
    return label.endswith(p.label) and label[: -len(p.label)] in COMBO_KEYWORDS


def _is_homoglyph_combo(label: str, p: ProtectedDomain) -> bool:
    """'secure-paypa1': a token is a look-alike (not exact) spelling of the protected name."""
    target = skeleton(p.label)
    tokens = _tokens(label)
    if len(tokens) < 2:
        return False
    for i in range(len(tokens)):
        for j in range(i + 1, len(tokens) + 1):
            joined = "-".join(tokens[i:j])
            if joined != p.label and skeleton(joined) == target and (j - i) < len(tokens):
                return True
    return False


def _label_finding(label: str, label_skel: str, suffix: str, p: ProtectedDomain, location: str,
                   shown: str, org: str, target: str, ev: dict) -> Finding | None:
    """At most one finding comparing the registrable name with one protected domain."""
    if label != p.label and label_skel == skeleton(p.label):
        return Finding("LOOKALIKE_HOMOGLYPH", Severity.HIGH,
                       f"{location} domain '{shown}' is visually confusable with {target}.", ev)
    if label == p.label:
        if suffix != p.suffix and p.kind == "org":
            return Finding("LOOKALIKE_TLD_SWAP", Severity.MEDIUM,
                           f"{location} domain '{org}' uses the same name as {target} with a different suffix.", ev)
        return None
    min_len = 5 if p.kind == "org" else 6
    if len(p.label) >= min_len:
        limit = 1 if len(p.label) < 10 else 2
        if edit_distance(label, p.label, limit) <= limit:
            return Finding("LOOKALIKE_TYPO", Severity.HIGH,
                           f"{location} domain '{shown}' is one typo away from {target}.", ev)
    if len(p.label) >= 4 and _is_combo(label, p):
        return Finding("LOOKALIKE_COMBO", Severity.MEDIUM,
                       f"{location} domain '{shown}' combines {target} with other words.", ev)
    if len(p.label) >= 4 and _is_homoglyph_combo(label, p):
        return Finding("LOOKALIKE_COMBO", Severity.HIGH,
                       f"{location} domain '{shown}' combines a look-alike spelling of {target} with other words.", ev)
    return None


def check_host(host: str | None, protected: list[ProtectedDomain], location: str) -> list[Finding]:
    """Findings for `host` (a domain or URL host) that imitates a protected domain."""
    if not host or not re.search(r"[^\d.:\[\]]", host):  # skip IP literals
        return []
    uhost = decode_idna(host)
    org = org_domain(uhost)
    if not org or "." not in org:
        return []
    by_domain = {p.domain: p for p in protected}
    ascii_org = org_domain(host.lower().rstrip("."))
    if org in by_domain or ascii_org in by_domain:
        return []

    label, suffix = org.split(".", 1)
    sub = uhost[: -len(org)].rstrip(".")
    label_skel = skeleton(label)
    ev_base = {"location": location, "host": host}
    shown = org
    if uhost != host.lower():
        ev_base["unicode_host"] = uhost
        shown = f"{org} ({org_domain(host.lower())})"

    out: list[Finding] = []
    for p in protected:
        ev = {**ev_base, "imitates": p.domain, "kind": p.kind}
        target = f"'{p.domain}'" + (f" ({p.brand})" if p.brand and p.brand != p.label else "")
        finding = _label_finding(label, label_skel, suffix, p, location, shown, org, target, ev)
        if finding:
            out.append(finding)
        # The subdomain is an independent signal: "paypal.com.secure-paypa1.com" is both.
        if sub:
            if p.domain in sub:
                out.append(Finding("LOOKALIKE_BRAND_IN_SUBDOMAIN", Severity.HIGH,
                                   f"{location} host '{uhost}' puts {target} in front of an unrelated domain '{org}'.", ev))
            elif len(p.label) >= 4 and p.label not in GENERIC_BRAND_LABELS and p.label in _tokens(sub):
                out.append(Finding("LOOKALIKE_BRAND_IN_SUBDOMAIN", Severity.MEDIUM,
                                   f"{location} host '{uhost}' uses '{p.label}' as a subdomain of unrelated '{org}'.", ev))

    for part in uhost.split("."):
        found = scripts(part)
        if len(found) > 1:
            confusable = bool(found & _CONFUSABLE_SCRIPTS) and "LATIN" in found
            out.append(Finding("LOOKALIKE_MIXED_SCRIPT", Severity.HIGH if confusable else Severity.MEDIUM,
                               f"{location} domain label '{part}' mixes scripts ({', '.join(sorted(found))}).",
                               {**ev_base, "label": part, "scripts": sorted(found)}))
            break
    return out
