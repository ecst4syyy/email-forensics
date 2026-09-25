"""Top-level orchestration: load evidence, run analyzers, build a report."""

from __future__ import annotations

from pathlib import Path

from .body import analyze_body
from .headers import analyze_headers
from .loader import load_eml
from .models import Report
from .rules import run_header_rules


def analyze_file(path: str | Path) -> Report:
    evidence, msg = load_eml(path)
    headers = analyze_headers(msg)
    findings = run_header_rules(msg, headers)
    body, body_findings = analyze_body(msg)
    findings += body_findings
    findings.sort(key=lambda f: (-f.severity.rank, f.code))
    return Report(evidence=evidence, headers=headers, body=body, findings=findings)
