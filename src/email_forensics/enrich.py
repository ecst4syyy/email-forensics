"""Opt-in enrichment of indicators with external intelligence.

Nothing here runs unless enrichment is explicitly enabled. Lookups reveal the
investigation to third parties, so:
- files are never uploaded: only hashes are looked up;
- every request is recorded (provider, what was asked, when, the answer) and a
  recording can be replayed later to reproduce a report offline;
- answers are cached on disk with an expiry, and providers are rate limited.

Providers: Team Cymru IP-to-ASN (DNS), RDAP domain registration, VirusTotal,
URLhaus, MalwareBazaar and AbuseIPDB (API keys from the environment).
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .domains import org_domain
from .iocs import Indicator
from .models import Finding, Severity
from .resolver import DnsError, Resolver

TIMEOUT = 15.0
MAX_RESPONSE = 2 * 1024 * 1024
DEFAULT_TTL = 24 * 3600
MAX_LOOKUPS_PER_PROVIDER = 50
NEW_DOMAIN_DAYS = 30
YOUNG_DOMAIN_DAYS = 180


class FetchError(Exception):
    pass


# --------------------------------------------------------------------------- HTTP


class Fetcher:
    name = "fetcher"

    def request(self, method: str, url: str, headers: dict | None = None, data: dict | None = None) -> dict:
        """Return the decoded JSON answer. Raise FetchError on failure. `headers` may hold secrets."""
        raise NotImplementedError


class HttpFetcher(Fetcher):
    name = "https"

    def request(self, method, url, headers=None, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, method=method, headers={
            "User-Agent": f"email-forensics/{__version__}", "Accept": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                raw = resp.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {"_status": 404}
            raise FetchError(f"HTTP {exc.code}") from exc
        except (OSError, ValueError) as exc:
            raise FetchError(str(exc)) from exc
        if len(raw) > MAX_RESPONSE:
            raise FetchError("response too large")
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise FetchError("response is not JSON") from exc


def _request_key(method: str, url: str, data: dict | None) -> str:
    return f"{method} {url}" + (f" {json.dumps(data, sort_keys=True)}" if data else "")


class ReplayFetcher(Fetcher):
    def __init__(self, path: str | Path) -> None:
        self.name = f"replay {path}"
        self._answers = {e["request"]: e for e in json.loads(Path(path).read_text(encoding="utf-8")).get("requests", [])}

    def request(self, method, url, headers=None, data=None):
        entry = self._answers.get(_request_key(method, url, data))
        if entry is None:
            raise FetchError("not in recording")
        if entry.get("error"):
            raise FetchError(entry["error"])
        return entry["response"]


@dataclass
class RecordedRequest:
    provider: str
    request: str  # method, URL and form data; never headers (API keys)
    at: str
    response: dict | None = None
    error: str | None = None
    cached: bool = False


class Recorder(Fetcher):
    """Wraps a fetcher with a disk cache and a log of every request (secrets excluded)."""

    def __init__(self, inner: Fetcher, cache_dir: str | Path | None = None, ttl: int = DEFAULT_TTL) -> None:
        self.inner, self.name = inner, inner.name
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.ttl = ttl
        self.log: list[RecordedRequest] = []
        self.provider = "?"

    def _cache_path(self, key: str) -> Path | None:
        if not self.cache_dir:
            return None
        return self.cache_dir / f"{hashlib.sha256(key.encode()).hexdigest()}.json"

    def offline(self, method: str, url: str, data: dict | None = None) -> bool:
        """True if answering this request needs no network (replay, or a fresh cache entry)."""
        if isinstance(self.inner, ReplayFetcher):
            return True
        path = self._cache_path(_request_key(method, url, data))
        try:
            return bool(path and path.is_file() and time.time() - json.loads(path.read_text())["stored"] < self.ttl)
        except (OSError, ValueError, KeyError):
            return False

    def request(self, method, url, headers=None, data=None):
        key = _request_key(method, url, data)
        entry = RecordedRequest(self.provider, key, datetime.now(timezone.utc).isoformat())
        path = self._cache_path(key)
        if path and path.is_file():
            try:
                cached = json.loads(path.read_text(encoding="utf-8"))
                if time.time() - cached["stored"] < self.ttl:
                    entry.response, entry.cached, entry.at = cached["response"], True, cached["at"]
                    self.log.append(entry)
                    return entry.response
            except (OSError, ValueError, KeyError):
                pass
        try:
            entry.response = self.inner.request(method, url, headers, data)
        except FetchError as exc:
            entry.error = str(exc)
            self.log.append(entry)
            raise
        self.log.append(entry)
        if path:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({"stored": time.time(), "at": entry.at, "response": entry.response}),
                                encoding="utf-8")
            except OSError:
                pass
        return entry.response

    def save(self, path: str | Path) -> None:
        data = {"fetcher": self.name, "requests": [vars(e) for e in self.log]}
        Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


# --------------------------------------------------------------------------- results


@dataclass
class EnrichmentRecord:
    provider: str
    kind: str  # ip, domain, url, sha256
    value: str
    summary: dict = field(default_factory=dict)
    error: str | None = None


@dataclass
class Enrichment:
    providers: list[str] = field(default_factory=list)
    records: list[EnrichmentRecord] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    requests: list[RecordedRequest] = field(default_factory=list)


# --------------------------------------------------------------------------- providers


class Provider:
    name = "provider"
    kinds: tuple[str, ...] = ()
    min_interval = 0.0  # seconds between requests

    def __init__(self) -> None:
        self.count = 0
        self._last = 0.0

    def available(self, ctx: "Enricher") -> str | None:
        """None if usable, else why not."""
        return None

    def throttle(self, sleep) -> None:
        wait = self._last + self.min_interval - time.monotonic()
        if wait > 0:
            sleep(wait)
        self._last = time.monotonic()

    def lookup(self, ctx: "Enricher", kind: str, value: str) -> dict:
        raise NotImplementedError


class CymruAsn(Provider):
    name, kinds = "cymru", ("ip",)

    def available(self, ctx):
        return None if ctx.resolver else "needs DNS (--online, --doh or --dns-replay)"

    def lookup(self, ctx, kind, value):
        ip = ipaddress.ip_address(value)
        if ip.version == 4:
            name = ".".join(reversed(value.split("."))) + ".origin.asn.cymru.com"
        else:
            name = ".".join(reversed(ip.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
        try:
            answers = ctx.resolver.query(name, "TXT")
        except DnsError as exc:
            raise FetchError(str(exc)) from exc
        if not answers:
            return {"asn": None}
        fields = [f.strip() for f in answers[0].split("|")]
        out = {"asn": fields[0].split()[0] if fields and fields[0] else None,
               "prefix": fields[1] if len(fields) > 1 else None,
               "country": fields[2] if len(fields) > 2 else None,
               "registry": fields[3] if len(fields) > 3 else None}
        if out["asn"]:
            try:
                names = ctx.resolver.query(f"AS{out['asn']}.asn.cymru.com", "TXT")
                if names:
                    out["as_name"] = names[0].split("|")[-1].strip()
            except DnsError:
                pass
        return out


class Rdap(Provider):
    name, kinds, min_interval = "rdap", ("domain",), 1.0
    base = "https://rdap.org/domain/"

    def lookup(self, ctx, kind, value):
        data = ctx.fetch(self, "GET", self.base + urllib.parse.quote(value))
        if data.get("_status") == 404:
            return {"registered": None, "status": "not found"}
        out = {"registered": None, "registrar": None, "status": data.get("status")}
        for event in data.get("events", []) or []:
            if event.get("eventAction") == "registration":
                out["registered"] = event.get("eventDate")
            elif event.get("eventAction") == "expiration":
                out["expires"] = event.get("eventDate")
        for entity in data.get("entities", []) or []:
            if "registrar" in (entity.get("roles") or []):
                vcard = entity.get("vcardArray", [None, []])[1] if isinstance(entity.get("vcardArray"), list) else []
                out["registrar"] = next((v[3] for v in vcard if isinstance(v, list) and v[:1] == ["fn"]), None)
        return out


class VirusTotal(Provider):
    name, kinds, min_interval = "virustotal", ("sha256", "domain", "ip", "url"), 15.0  # public API: 4/min
    base = "https://www.virustotal.com/api/v3/"

    def available(self, ctx):
        return None if os.environ.get("VT_API_KEY") else "set VT_API_KEY"

    def lookup(self, ctx, kind, value):
        path = {"sha256": f"files/{value}", "domain": f"domains/{value}", "ip": f"ip_addresses/{value}",
                "url": "urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")}[kind]
        data = ctx.fetch(self, "GET", self.base + path, headers={"x-apikey": os.environ["VT_API_KEY"]})
        if data.get("_status") == 404:
            return {"known": False}
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        return {"known": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0), "label": (attrs.get("popular_threat_classification") or {})
                .get("suggested_threat_label"), "reputation": attrs.get("reputation")}


class UrlHaus(Provider):
    name, kinds, min_interval = "urlhaus", ("url", "domain", "sha256"), 1.0
    base = "https://urlhaus-api.abuse.ch/v1/"

    def available(self, ctx):
        return None if _abuse_key() else "set ABUSE_CH_API_KEY"

    def lookup(self, ctx, kind, value):
        endpoint, form = {"url": ("url/", {"url": value}), "domain": ("host/", {"host": value}),
                          "sha256": ("payload/", {"sha256_hash": value})}[kind]
        data = ctx.fetch(self, "POST", self.base + endpoint, headers={"Auth-Key": _abuse_key()}, data=form)
        listed = data.get("query_status") == "ok"
        out = {"listed": listed}
        if listed:
            out.update({"threat": data.get("threat"), "status": data.get("url_status") or data.get("urlhaus_reference"),
                        "tags": data.get("tags"), "signature": data.get("signature"),
                        "urls": data.get("url_count")})
        return out


class MalwareBazaar(Provider):
    name, kinds, min_interval = "malwarebazaar", ("sha256",), 1.0
    base = "https://mb-api.abuse.ch/api/v1/"

    def available(self, ctx):
        return None if _abuse_key() else "set ABUSE_CH_API_KEY"

    def lookup(self, ctx, kind, value):
        data = ctx.fetch(self, "POST", self.base, headers={"Auth-Key": _abuse_key()},
                         data={"query": "get_info", "hash": value})
        if data.get("query_status") != "ok":
            return {"known": False}
        info = (data.get("data") or [{}])[0]
        return {"known": True, "signature": info.get("signature"), "file_type": info.get("file_type"),
                "first_seen": info.get("first_seen"), "tags": info.get("tags")}


class AbuseIpdb(Provider):
    name, kinds, min_interval = "abuseipdb", ("ip",), 1.0
    base = "https://api.abuseipdb.com/api/v2/check?"

    def available(self, ctx):
        return None if os.environ.get("ABUSEIPDB_API_KEY") else "set ABUSEIPDB_API_KEY"

    def lookup(self, ctx, kind, value):
        url = self.base + urllib.parse.urlencode({"ipAddress": value, "maxAgeInDays": 90})
        data = (ctx.fetch(self, "GET", url, headers={"Key": os.environ["ABUSEIPDB_API_KEY"]}).get("data") or {})
        return {"confidence": data.get("abuseConfidenceScore"), "reports": data.get("totalReports"),
                "isp": data.get("isp"), "usage": data.get("usageType"), "country": data.get("countryCode"),
                "tor": data.get("isTor")}


def _abuse_key() -> str | None:
    return os.environ.get("ABUSE_CH_API_KEY") or os.environ.get("URLHAUS_API_KEY")


PROVIDERS = {p.name: p for p in (CymruAsn, Rdap, VirusTotal, UrlHaus, MalwareBazaar, AbuseIpdb)}


# --------------------------------------------------------------------------- orchestration


class Enricher:
    def __init__(self, fetcher: Fetcher, resolver: Resolver | None = None, providers: list[str] | None = None,
                 sleep=time.sleep, max_lookups: int = MAX_LOOKUPS_PER_PROVIDER) -> None:
        self.fetcher = fetcher if isinstance(fetcher, Recorder) else Recorder(fetcher)
        self.resolver = resolver
        self.sleep = sleep
        self.max_lookups = max_lookups
        unknown = set(providers or []) - set(PROVIDERS)
        if unknown:
            raise ValueError(f"unknown enrichment provider(s): {', '.join(sorted(unknown))}")
        self.providers = [PROVIDERS[n]() for n in (providers or PROVIDERS)]
        self._results: dict[tuple[str, str, str], EnrichmentRecord] = {}

    def fetch(self, provider: Provider, method: str, url: str, headers=None, data=None) -> dict:
        if not self.fetcher.offline(method, url, data):  # only real network calls are rate limited
            provider.throttle(self.sleep)
        self.fetcher.provider = provider.name
        return self.fetcher.request(method, url, headers, data)

    def enrich(self, indicators: list[Indicator], message_date: datetime | None = None) -> tuple[Enrichment, list[Finding]]:
        result = Enrichment()
        targets = _targets(indicators)
        start = len(self.fetcher.log)
        for p in self.providers:
            why = p.available(self)
            if why:
                result.skipped.append(f"{p.name}: {why}")
                continue
            result.providers.append(p.name)
            for kind, value in targets:
                if kind not in p.kinds:
                    continue
                key = (p.name, kind, value)
                if key not in self._results:  # reuse answers across messages in one run
                    if p.count >= self.max_lookups:
                        result.skipped.append(f"{p.name}: lookup limit of {self.max_lookups} reached")
                        break
                    p.count += 1
                    record = EnrichmentRecord(p.name, kind, value)
                    try:
                        record.summary = p.lookup(self, kind, value)
                    except (FetchError, ValueError, KeyError, TypeError, AttributeError) as exc:
                        record.error = str(exc)[:200]
                    self._results[key] = record
                result.records.append(self._results[key])
        result.requests = self.fetcher.log[start:]
        return result, _findings(result, message_date)


def _targets(indicators: list[Indicator]) -> list[tuple[str, str]]:
    """What to look up: public IPs, registrable domains, URLs and file hashes."""
    out: dict[tuple[str, str], None] = {}
    for ind in indicators:
        if ind.type in ("ipv4", "ipv6"):
            try:
                if not ipaddress.ip_address(ind.value).is_global:
                    continue
            except ValueError:
                continue
            out[("ip", ind.value)] = None
        elif ind.type == "domain":
            od = org_domain(ind.value)
            if od and "." in od:
                out[("domain", od)] = None
        elif ind.type == "url":
            out[("url", ind.value)] = None
        elif ind.type == "sha256":
            out[("sha256", ind.value.lower())] = None
    return list(out)


def _age_days(iso: str | None, at: datetime) -> float | None:
    if not iso:
        return None
    try:
        when = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (at - when).total_seconds() / 86400


def _findings(result: Enrichment, message_date: datetime | None) -> list[Finding]:
    out: list[Finding] = []
    now = datetime.now(timezone.utc)
    for r in result.records:
        s, ev = r.summary, {"provider": r.provider, "value": r.value, **{k: v for k, v in r.summary.items() if v}}
        if r.error:
            continue
        if r.provider == "rdap" and s.get("registered"):
            at_send = _age_days(s["registered"], message_date or now)
            if at_send is not None and at_send < YOUNG_DOMAIN_DAYS:
                sev = Severity.HIGH if at_send < NEW_DOMAIN_DAYS else Severity.MEDIUM
                out.append(Finding("ENRICH_NEW_DOMAIN", sev,
                                   f"Domain {r.value} was registered {max(0, at_send):.0f} days before the message "
                                   f"was sent ({s['registered'][:10]}).", {**ev, "age_days": round(at_send, 1)}))
        elif r.provider == "virustotal" and s.get("known"):
            bad = (s.get("malicious") or 0) + (s.get("suspicious") or 0)
            if bad:
                code = "ENRICH_KNOWN_MALWARE" if r.kind == "sha256" and (s.get("malicious") or 0) >= 5 else "ENRICH_VT_DETECTIONS"
                sev = Severity.HIGH if (s.get("malicious") or 0) >= 3 else Severity.MEDIUM
                out.append(Finding(code, sev, f"VirusTotal: {s.get('malicious', 0)} engines flag {r.kind} {r.value}"
                                   + (f" ({s['label']})" if s.get("label") else "") + ".", ev))
        elif r.provider == "urlhaus" and s.get("listed"):
            out.append(Finding("ENRICH_URLHAUS_LISTED", Severity.HIGH,
                               f"URLhaus lists {r.kind} {r.value} as a malware distribution site"
                               + (f" ({s['threat']})" if s.get("threat") else "") + ".", ev))
        elif r.provider == "malwarebazaar" and s.get("known"):
            out.append(Finding("ENRICH_KNOWN_MALWARE", Severity.HIGH,
                               f"MalwareBazaar knows {r.value}" + (f" as {s['signature']}" if s.get("signature") else "")
                               + ".", ev))
        elif r.provider == "abuseipdb" and (s.get("confidence") or 0) >= 25:
            sev = Severity.HIGH if s["confidence"] >= 75 else Severity.MEDIUM
            out.append(Finding("ENRICH_ABUSIVE_IP", sev, f"AbuseIPDB: {r.value} has abuse confidence {s['confidence']}% "
                               f"({s.get('reports')} reports).", ev))
        elif r.provider == "cymru" and s.get("asn"):
            out.append(Finding("ENRICH_IP_ASN", Severity.INFO,
                               f"{r.value} is in AS{s['asn']} {s.get('as_name') or ''} ({s.get('country') or '?'}).".replace("  ", " "),
                               ev))
    errors = [r for r in result.records if r.error]
    if errors:
        out.append(Finding("ENRICH_ERRORS", Severity.INFO, f"{len(errors)} enrichment lookup(s) failed.",
                           {"errors": [f"{r.provider} {r.value}: {r.error}" for r in errors[:10]]}))
    return out
