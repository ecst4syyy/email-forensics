"""Public Suffix List lookups (https://publicsuffix.org), from a bundled snapshot.

The registrable ("organisational") domain is the public suffix plus one label:
``mail.example.co.uk`` -> ``example.co.uk``. DMARC alignment and lookalike
comparison depend on getting this right.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

_DATA = "public_suffix_list.dat"


@lru_cache(maxsize=1)
def _rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Return (exact rules, wildcard parents, exceptions), each in Unicode and punycode form."""
    exact, wildcard, exception = set(), set(), set()
    text = resources.files("email_forensics").joinpath("data", _DATA).read_text(encoding="utf-8")
    for line in text.splitlines():
        rule = line.strip().split(" ", 1)[0].lower()
        if not rule or rule.startswith("//"):
            continue
        for form in {rule, _to_ascii(rule)}:
            if form.startswith("!"):
                exception.add(form[1:])
            elif form.startswith("*."):
                wildcard.add(form[2:])
            else:
                exact.add(form)
    return frozenset(exact), frozenset(wildcard), frozenset(exception)


def _to_ascii(rule: str) -> str:
    prefix = rule[0] if rule[:1] == "!" else ""
    body = rule[len(prefix):]
    try:
        return prefix + ".".join(
            label if label == "*" or label.isascii() else "xn--" + label.encode("punycode").decode("ascii")
            for label in body.split(".")
        )
    except UnicodeError:
        return rule


def public_suffix(host: str) -> str:
    """The longest matching public suffix (the implicit '*' rule makes the TLD the fallback)."""
    exact, wildcard, exception = _rules()
    labels = host.lower().rstrip(".").split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exception:
            return ".".join(labels[i + 1:])
        if candidate in exact:
            return candidate
        parent = ".".join(labels[i + 1:])
        if i + 1 < len(labels) and parent in wildcard:
            return candidate
    return labels[-1]


def registrable_domain(host: str | None) -> str | None:
    """Public suffix plus one label, or the host itself when it is a bare suffix or single label."""
    if not host:
        return None
    host = host.lower().strip().rstrip(".")
    if not host:
        return None
    suffix = public_suffix(host)
    if host == suffix:
        return host
    rest = host[: -len(suffix) - 1]
    return f"{rest.rsplit('.', 1)[-1]}.{suffix}"
