"""An in-memory resolver for tests."""

from email_forensics.resolver import DnsError, Resolver


class FakeResolver(Resolver):
    name = "fake"

    def __init__(self, records: dict[tuple[str, str], list[str] | Exception]):
        self.records = {(n.lower(), t.upper()): v for (n, t), v in records.items()}
        self.queries: list[tuple[str, str]] = []

    def query(self, name, rtype):
        self.queries.append((name, rtype))
        value = self.records.get((name.lower().rstrip("."), rtype.upper()), [])
        if isinstance(value, Exception):
            raise DnsError(str(value))
        return list(value)
