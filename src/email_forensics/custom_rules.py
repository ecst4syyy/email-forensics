"""Organisation-specific detection and suppression rules (JSON, or TOML on Python 3.11+).

Example (TOML)::

    [[rule]]
    id = "WIRE_FRAUD"
    description = "Payment request from outside with a reply-to elsewhere"
    severity = "high"
    all = [
      { field = "subject", matches = "(?i)wire|payment|invoice|iban" },
      { finding = "HDR_REPLY_TO_MISMATCH" },
    ]
    none = [ { field = "from_domain", in = ["acme-corp.com"] } ]

    [[rule]]
    id = "PARTNER_NEWSLETTER"
    action = "suppress"
    suppress = ["URL_TEXT_MISMATCH", "HTML_TRACKING_PIXEL"]
    all = [ { field = "from_domain", equals = "news.partner.example" }, { field = "auth:dmarc", equals = "pass" } ]

A rule matches when every ``all`` condition, at least one ``any`` condition (if
given) and no ``none`` condition holds. List fields match if any element does.
``flag`` rules (default) add a ``RULE_<ID>`` finding; ``suppress`` rules remove the
listed finding codes (recorded in the report as suppressed, never silently).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .domains import domain_of, org_domain
from .headers import raw_headers
from .models import Finding, Report, Severity

MAX_TEXT = 1_000_000
_OPERATORS = ("equals", "contains", "matches", "in", "exists", "gt", "gte", "lt", "lte", "startswith", "endswith")
FIELDS = ("subject", "from", "from_domain", "from_org_domain", "from_display_name", "reply_to", "reply_to_domain",
          "return_path", "return_path_domain", "sender", "to", "cc", "recipient_domains", "message_id", "mailer",
          "body", "url", "url_host", "attachment_name", "attachment_ext", "attachment_type", "attachment_sha256",
          "origin_ip", "received_ip", "score", "verdict", "findings", "format")


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    action: str = "flag"
    suppress: list[str] = field(default_factory=list)
    all: list[dict] = field(default_factory=list)
    any: list[dict] = field(default_factory=list)
    none: list[dict] = field(default_factory=list)
    source: str = ""


@dataclass
class Suppressed:
    code: str
    rule: str
    message: str


def load_rules(paths: list[str | Path]) -> list[Rule]:
    rules: list[Rule] = []
    for path in map(Path, paths):
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".toml":
            try:
                import tomllib
            except ImportError as exc:  # Python 3.10
                raise RuleError("TOML rules need Python 3.11+; use JSON instead") from exc
            data = tomllib.loads(text)
        else:
            data = json.loads(text)
        if isinstance(data, dict):
            items = data.get("rule") or data.get("rules") or []
        else:
            items = data
        if not isinstance(items, list):
            raise RuleError(f"{path}: expected a list of rules")
        for i, item in enumerate(items):
            rules.append(_parse_rule(item, f"{path}#{i + 1}"))
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"duplicate rule id(s): {', '.join(sorted(dupes))}")
    return rules


def _parse_rule(item: dict, source: str) -> Rule:
    if not isinstance(item, dict) or not item.get("id"):
        raise RuleError(f"{source}: every rule needs an id")
    rid = str(item["id"])
    if not re.fullmatch(r"[A-Za-z0-9_]{1,60}", rid):
        raise RuleError(f"{source}: rule id must be letters, digits and underscores")
    try:
        severity = Severity(str(item.get("severity", "medium")).lower())
    except ValueError as exc:
        raise RuleError(f"{source}: unknown severity {item.get('severity')!r}") from exc
    action = item.get("action", "flag")
    if action not in ("flag", "suppress"):
        raise RuleError(f"{source}: action must be flag or suppress")
    rule = Rule(rid.upper(), str(item.get("description", "")), severity, action,
                [str(c) for c in item.get("suppress", [])], list(item.get("all", [])), list(item.get("any", [])),
                list(item.get("none", [])), source)
    if not (rule.all or rule.any):
        raise RuleError(f"{source}: rule {rid} has no 'all' or 'any' conditions")
    if action == "suppress" and not rule.suppress:
        raise RuleError(f"{source}: suppress rule {rid} lists no finding codes")
    for cond in rule.all + rule.any + rule.none:
        _check_condition(cond, source)
    return rule


def _check_condition(cond: dict, source: str) -> None:
    if not isinstance(cond, dict):
        raise RuleError(f"{source}: conditions must be tables/objects")
    if "finding" in cond or "finding_prefix" in cond:
        return
    name = cond.get("field", "")
    if name not in FIELDS and not name.startswith(("header:", "auth:")):
        raise RuleError(f"{source}: unknown field {name!r}")
    ops = [op for op in _OPERATORS if op in cond]
    if len(ops) != 1:
        raise RuleError(f"{source}: condition on {name!r} needs exactly one of {', '.join(_OPERATORS)}")
    if ops[0] == "matches":
        try:
            re.compile(cond["matches"])
        except re.error as exc:
            raise RuleError(f"{source}: bad regex {cond['matches']!r}: {exc}") from exc


# --------------------------------------------------------------------------- evaluation


def _values(report: Report, msg, name: str) -> list:
    h, b = report.headers, report.body
    a = report.assessment
    if name.startswith("header:"):
        return raw_headers(msg, name[7:]) if msg is not None else []
    if name.startswith("auth:"):
        return [r.result for r in h.auth_results if r.method == name[5:].lower()]
    simple = {
        "subject": [h.subject], "from": [h.from_address], "from_domain": [domain_of(h.from_address)],
        "from_org_domain": [org_domain(domain_of(h.from_address))], "from_display_name": [h.from_display_name],
        "reply_to": h.reply_to, "reply_to_domain": [domain_of(x) for x in h.reply_to],
        "return_path": [h.return_path], "return_path_domain": [domain_of(h.return_path)], "sender": [h.sender],
        "to": h.to, "cc": h.cc, "recipient_domains": report.identity.recipient_domains,
        "message_id": [h.message_id], "mailer": [h.x_mailer],
        "body": [tb.preview[:MAX_TEXT] for tb in b.text_bodies],
        "url": [u.url for u in b.urls] + [u.url for at in report.attachments for u in at.urls],
        "url_host": [u.host for u in b.urls if u.host] + [u.host for at in report.attachments for u in at.urls if u.host],
        "attachment_name": [at.filename for at in report.attachments],
        "attachment_ext": [at.extension for at in report.attachments],
        "attachment_type": [at.detected_type for at in report.attachments],
        "attachment_sha256": [at.sha256 for at in report.attachments],
        "origin_ip": [next((hop.from_ip for hop in h.hops if hop.from_ip and hop.ip_is_private is False), None)],
        "received_ip": [hop.from_ip for hop in h.hops if hop.from_ip],
        "score": [a.score if a else None], "verdict": [a.verdict if a else None],
        "findings": [f.code for f in report.findings], "format": [report.evidence.format],
    }
    return [v for v in simple.get(name, []) if v is not None]


def _test(value, op: str, expected) -> bool:
    if op == "exists":
        return bool(expected)
    if op in ("gt", "gte", "lt", "lte"):
        try:
            v, e = float(value), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gt": v > e, "gte": v >= e, "lt": v < e, "lte": v <= e}[op]
    v = str(value)
    if op == "matches":
        return re.search(expected, v[:MAX_TEXT]) is not None
    lv = v.lower()
    if op == "equals":
        return lv == str(expected).lower()
    if op == "contains":
        return str(expected).lower() in lv
    if op == "startswith":
        return lv.startswith(str(expected).lower())
    if op == "endswith":
        return lv.endswith(str(expected).lower())
    if op == "in":
        return lv in {str(x).lower() for x in expected}
    return False


def _holds(cond: dict, report: Report, msg) -> tuple[bool, str]:
    if "finding" in cond or "finding_prefix" in cond:
        min_rank = Severity(cond.get("min_severity", "info")).rank
        want = cond.get("finding")
        prefix = cond.get("finding_prefix")
        hits = [f.code for f in report.findings if f.severity.rank >= min_rank
                and ((want and f.code == want) or (prefix and f.code.startswith(prefix)))]
        return bool(hits), f"finding {hits[0]}" if hits else ""
    name = cond["field"]
    op = next(o for o in _OPERATORS if o in cond)
    values = _values(report, msg, name)
    if op == "exists":
        return bool(values) == bool(cond["exists"]), f"{name} exists={bool(values)}"
    hit = next((v for v in values if _test(v, op, cond[op])), None)
    return hit is not None, f"{name}={str(hit)[:80]}" if hit is not None else ""


def evaluate(rules: list[Rule], report: Report, msg=None) -> tuple[list[Finding], list[Suppressed]]:
    """Apply rules to a report. Returns new findings, and removes suppressed ones from report.findings."""
    added: list[Finding] = []
    suppressed: list[Suppressed] = []
    for rule in rules:
        results = [_holds(c, report, msg) for c in rule.all]
        if not all(ok for ok, _ in results):
            continue
        any_results = [_holds(c, report, msg) for c in rule.any]
        if rule.any and not any(ok for ok, _ in any_results):
            continue
        if any(_holds(c, report, msg)[0] for c in rule.none):
            continue
        why = [w for ok, w in results + any_results if ok and w]
        if rule.action == "suppress":
            keep = []
            for f in report.findings:
                if f.code in rule.suppress:
                    suppressed.append(Suppressed(f.code, rule.id, f.message))
                else:
                    keep.append(f)
            report.findings = keep
        else:
            added.append(Finding(f"RULE_{rule.id}", rule.severity,
                                 f"Custom rule {rule.id} matched" + (f": {rule.description}" if rule.description else "") + ".",
                                 {"rule": rule.id, "source": rule.source, "matched": why[:10]}))
    return added, suppressed
