"""Domain helpers shared by header, URL and authentication analysis."""

from __future__ import annotations

from .psl import registrable_domain


def domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().strip(">").rstrip(".").lower() or None


def org_domain(domain: str | None) -> str | None:
    """Organisational (registrable) domain per the Public Suffix List."""
    return registrable_domain(domain)
