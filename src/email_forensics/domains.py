"""Domain helpers shared by header and URL analysis."""

from __future__ import annotations

# Rough second-level suffixes so "mail.example.co.uk" and "example.co.uk" compare equal.
# A full Public Suffix List lookup is planned for a later day.
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "ne", "or"}


def domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().strip(">").rstrip(".").lower() or None


def org_domain(domain: str | None) -> str | None:
    """Approximate organizational domain (without a Public Suffix List)."""
    if not domain:
        return None
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
