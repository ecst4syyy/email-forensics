"""Explainable risk scoring: findings -> a 0-100 score, a verdict and the reasons.

Design:
- Each finding contributes points by severity, within a category (sender identity,
  authentication, links, attachments, payload, ...).
- Inside a category, contributions have diminishing returns, so many related
  findings (e.g. five URL findings for one phishing link) do not dominate.
- A few findings are near-conclusive evidence of malice and set a score floor.
- An attached (nested) message's score counts towards its parent.
Points are never subtracted: passing authentication is not evidence of good intent
(attackers authenticate their own lookalike domains).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from .models import Finding, Report, Severity

SEVERITY_POINTS = {Severity.HIGH: 25.0, Severity.MEDIUM: 10.0, Severity.LOW: 3.0, Severity.INFO: 0.0}
DIMINISHING = 0.6  # each further finding in a category counts 60% of the previous one
CATEGORY_CAP = 60.0
SCALE = 50.0  # raw points -> score: 100 * (1 - exp(-raw / SCALE))

VERDICTS = ((70, "malicious"), (35, "suspicious"), (12, "caution"), (0, "clean"))

# Findings that on their own are strong evidence of a malicious message.
CONCLUSIVE = {
    "MACRO_MALICIOUS_PATTERN": 85, "MACRO_STOMPED": 85, "MACRO_XLM": 75, "DOC_DDE": 80,
    "DOC_EXTERNAL_OBJECT": 75, "RTF_EXPLOIT_CLASS": 85, "PDF_LAUNCH": 80, "LNK_RUNS_COMMAND": 90,
    "SCRIPT_DOWNLOADER": 85, "SCRIPT_ENCODED_COMMAND": 80, "SCRIPT_RANSOMWARE": 90,
    "ATT_HTML_SMUGGLING": 85, "HTML_CREDENTIAL_FORM": 75, "ATT_DOUBLE_EXTENSION": 75,
    "HDR_MAILER_PHISHING_KIT": 75, "PROVIDER_PHISH_VERDICT": 75, "PROVIDER_EXTERNAL_CLAIMS_INTERNAL": 75,
    "ATT_ZIP_BOMB": 70,
}

_PREFIX_CATEGORIES = (
    (("LOOKALIKE_",), "lookalike"),
    (("HDR_DISPLAY_NAME", "HDR_REPLY_TO", "HDR_RETURN_PATH", "HDR_SENDER", "HDR_MULTIPLE_FROM",
      "HDR_PROVIDER_PATH", "HDR_MESSAGE_ID"), "sender identity"),
    (("AUTH_", "AUTHV_", "PROVIDER_"), "authentication"),
    (("URL_", "HTML_"), "links and content"),
    (("ATT_",), "attachments"),
    (("MACRO_", "DOC_", "PDF_", "LNK_", "SCRIPT_", "ONENOTE_", "RTF_"), "payload"),
    (("HDR_MAILER", "HDR_PHP"), "sending software"),
    (("NESTED_",), "attached messages"),
    (("RCV_", "HDR_", "PARSE_", "MIME_", "BODY_", "TEXT_"), "structure and evasion"),
    (("MSG_",), "context"),
)


def category_of(finding: Finding) -> str:
    code = finding.code
    if code.startswith("LOOKALIKE_"):
        return "links and content" if finding.evidence.get("location") == "URL" else "sender identity"
    for prefixes, name in _PREFIX_CATEGORIES:
        if code.startswith(prefixes):
            return name
    return "other"


@dataclass
class Reason:
    code: str
    severity: str
    category: str
    points: float
    message: str


@dataclass
class Assessment:
    score: int
    verdict: str
    reasons: list[Reason] = field(default_factory=list)
    categories: dict[str, float] = field(default_factory=dict)
    floor: str | None = None  # the conclusive finding that set a minimum score, if any
    nested_score: int | None = None


def verdict_for(score: int) -> str:
    return next(name for threshold, name in VERDICTS if score >= threshold)


def assess(report: Report) -> Assessment:
    """Score a report (and its nested reports, which are assessed first)."""
    nested_scores = []
    for n in report.nested:
        n.report.assessment = assess(n.report)
        nested_scores.append(n.report.assessment.score)

    by_category: dict[str, list[Finding]] = {}
    for f in report.findings:
        if f.code.startswith("NESTED_"):  # represented by the nested score instead
            continue
        by_category.setdefault(category_of(f), []).append(f)

    reasons: list[Reason] = []
    categories: dict[str, float] = {}
    for cat, findings in by_category.items():
        findings.sort(key=lambda f: -SEVERITY_POINTS[f.severity])
        total = 0.0
        for i, f in enumerate(findings):
            pts = SEVERITY_POINTS[f.severity] * (DIMINISHING ** i)
            pts = min(pts, max(0.0, CATEGORY_CAP - total))
            total += pts
            if pts > 0:
                reasons.append(Reason(f.code, f.severity.value, cat, round(pts, 1), f.message))
        if total:
            categories[cat] = round(total, 1)

    raw = sum(categories.values())
    score = round(100 * (1 - math.exp(-raw / SCALE)))
    floor_code = None
    for f in report.findings:
        floor = CONCLUSIVE.get(f.code)
        if floor and floor > score:
            score, floor_code = floor, f.code
    nested_max = max(nested_scores, default=None)
    if nested_max is not None and nested_max > score:
        score = nested_max
        worst = max(report.nested, key=lambda n: n.report.assessment.score)
        reasons.append(Reason("NESTED_MESSAGE_SUSPICIOUS", "high" if nested_max >= 70 else "medium", "attached messages",
                              float(nested_max), f"Attached message {worst.part} scored {nested_max} "
                              f"({worst.report.assessment.verdict})."))
    reasons.sort(key=lambda r: -r.points)
    return Assessment(score=score, verdict=verdict_for(score), reasons=reasons[:10], categories=categories,
                      floor=floor_code, nested_score=nested_max)
