"""Top-level orchestration: load evidence, run analyzers, build a report."""

from __future__ import annotations

from pathlib import Path

from .attachments import analyze_attachments, correlate_with_body, extract_attachments
from .body import analyze_body
from .headers import analyze_headers
from .identity import analyze_identity
from .loader import load_eml
from .mime import walk_mime
from .models import Report
from .rules import run_header_rules


def analyze_file(path: str | Path, extract_dir: str | Path | None = None,
                 protected_domains: list[str] = ()) -> Report:
    evidence, msg = load_eml(path)
    headers = analyze_headers(msg)
    findings = run_header_rules(msg, headers)
    tree = walk_mime(msg)
    body, body_findings = analyze_body(msg, tree)
    attachments, attachment_findings = analyze_attachments(tree)
    correlate_with_body(attachment_findings, [tb.preview for tb in body.text_bodies])
    if extract_dir is not None and attachments:
        extract_attachments(tree, attachments, extract_dir, evidence.sha256)
    identity, identity_findings = analyze_identity(msg, headers, body, attachments, protected_domains)
    findings += body_findings + attachment_findings + identity_findings
    findings.sort(key=lambda f: (-f.severity.rank, f.code))
    return Report(evidence=evidence, headers=headers, body=body, attachments=attachments,
                  identity=identity, findings=findings)
