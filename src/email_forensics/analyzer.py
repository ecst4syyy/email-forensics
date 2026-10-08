"""Top-level orchestration: load evidence, run analyzers, build reports.

`analyze_message` is the core used for every input: a .eml file, a converted
.msg, one message of an mbox, or an email attached to another email (analysed
recursively, so a user-reported phish forwarded as an attachment gets a full
report of its own).
"""

from __future__ import annotations

import signal
from collections.abc import Iterator
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path

from .attachments import analyze_attachments, correlate_with_body, extract_attachments
from .auth import verify_authentication
from .body import analyze_body
from .headers import analyze_headers
from . import yara_scan
from .custom_rules import Rule
from .custom_rules import evaluate as evaluate_rules
from .enrich import Enricher
from .identity import analyze_identity
from .iocs import extract_iocs
from .loader import EvidenceError, _info, detect_format, iter_mbox, load_evidence, load_msg_bytes, parse_bytes
from .mime import MESSAGE_TYPES, MimeTree, walk_mime
from .models import (BodyAnalysis, EvidenceInfo, Finding, HeaderAnalysis, IdentityAnalysis, NestedReport, Report,
                     Severity)
from .msg import MsgInfo, is_msg
from .resolver import RecordingResolver
from .rules import run_header_rules
from .scoring import assess

MAX_NESTED_DEPTH = 3
MAX_NESTED_PER_MESSAGE = 20


@dataclass
class AnalysisOptions:
    extract_dir: str | Path | None = None
    protected_domains: list[str] = field(default_factory=list)
    resolver: RecordingResolver | None = None
    spf_ip: str | None = None
    max_nested_depth: int = MAX_NESTED_DEPTH
    enricher: Enricher | None = None
    timeout: float | None = None  # seconds per message (POSIX only)
    yara_rules: object | None = None  # compiled yara.Rules
    custom_rules: list[Rule] = field(default_factory=list)


def analyze_file(path: str | Path, extract_dir: str | Path | None = None,
                 protected_domains: list[str] = (), resolver: RecordingResolver | None = None,
                 spf_ip: str | None = None) -> Report:
    """Analyze one .eml or .msg file. `resolver` enables online authentication checks."""
    options = AnalysisOptions(extract_dir, list(protected_domains), resolver, spf_ip)
    evidence, raw, msg, msg_info = load_evidence(path)
    return analyze_message(evidence, raw, msg, options, msg_info)


def analyze_path(path: str | Path, options: AnalysisOptions | None = None) -> Iterator[Report]:
    """Analyze any supported file: yields one report per message (mbox) or a single report."""
    options = options or AnalysisOptions()
    if not Path(path).is_file():
        raise EvidenceError(f"not a file: {path}")
    if detect_format(path) == "mbox":
        for evidence, raw, msg in iter_mbox(path):
            yield analyze_with_timeout(evidence, raw, msg, options)
        return
    evidence, raw, msg, msg_info = load_evidence(path)
    yield analyze_with_timeout(evidence, raw, msg, options, msg_info)


def analyze_with_timeout(evidence: EvidenceInfo, raw: bytes, msg: EmailMessage, options: AnalysisOptions,
                         msg_info: MsgInfo | None = None) -> Report:
    """analyze_message with a wall-clock limit; a message that runs out of time still gets a
    (minimal) report so it is never silently dropped from a batch."""
    if not options.timeout or not hasattr(signal, "setitimer"):
        return analyze_message(evidence, raw, msg, options, msg_info)

    def on_alarm(signum, frame):
        raise AnalysisTimeout()

    previous = signal.signal(signal.SIGALRM, on_alarm)
    signal.setitimer(signal.ITIMER_REAL, options.timeout)
    try:
        return analyze_message(evidence, raw, msg, options, msg_info)
    except AnalysisTimeout:
        signal.setitimer(signal.ITIMER_REAL, 0)
        try:
            headers = analyze_headers(msg)
        except Exception:  # noqa: BLE001
            headers = HeaderAnalysis()
        report = Report(evidence=evidence, headers=headers, msg=msg_info, findings=[Finding(
            "ANALYSIS_TIMEOUT", Severity.MEDIUM,
            f"Analysis did not finish within {options.timeout:g}s; results are incomplete. Messages crafted to "
            "exhaust analyzers are themselves suspicious.", {"timeout_seconds": options.timeout})])
        report.assessment = assess(report)
        return report
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class AnalysisTimeout(Exception):
    pass


def analyze_message(evidence: EvidenceInfo, raw: bytes, msg: EmailMessage, options: AnalysisOptions,
                    msg_info: MsgInfo | None = None, depth: int = 0) -> Report:
    errors: list[Finding] = []

    def stage(name: str, fn, default):
        """Run one analyzer; an unexpected bug in it must not lose the rest of the report."""
        try:
            return fn()
        except (AnalysisTimeout, KeyboardInterrupt, MemoryError):
            raise
        except Exception as exc:  # noqa: BLE001 - isolation is the point
            errors.append(Finding("ANALYZER_ERROR", Severity.LOW,
                                  f"The {name} analyzer failed ({type(exc).__name__}); its results are missing "
                                  "from this report.", {"stage": name, "error": f"{type(exc).__name__}: {exc}"[:300]}))
            return default

    headers = stage("header", lambda: analyze_headers(msg), None) or HeaderAnalysis()
    findings = stage("header rules", lambda: run_header_rules(msg, headers), [])
    tree = stage("MIME", lambda: walk_mime(msg), None) or MimeTree()
    body, body_findings = stage("body", lambda: analyze_body(msg, tree), (BodyAnalysis(parts=tree.parts), []))
    attachments, attachment_findings = stage("attachment", lambda: analyze_attachments(tree), ([], []))
    stage("password correlation",
          lambda: correlate_with_body(attachment_findings, [tb.preview for tb in body.text_bodies]), None)
    if options.extract_dir is not None and attachments:
        extract_attachments(tree, attachments, options.extract_dir, evidence.sha256)  # I/O errors must surface
    identity, identity_findings = stage(
        "identity", lambda: analyze_identity(msg, headers, body, attachments, options.protected_domains),
        (IdentityAnalysis(), []))
    auth, auth_findings = stage(
        "authentication", lambda: verify_authentication(raw, msg, headers, options.resolver, options.spf_ip,
                                                        reconstructed=evidence.converted), (None, []))
    findings += body_findings + attachment_findings + identity_findings + auth_findings

    nested = (stage("attached message", lambda: _analyze_nested(tree, evidence, options, depth), [])
              if depth < options.max_nested_depth else [])
    findings += _nested_findings(nested)
    if msg_info is not None:
        findings += _msg_findings(msg_info)
    report = Report(evidence=evidence, headers=headers, body=body, attachments=attachments, identity=identity,
                    auth=auth, msg=msg_info, nested=nested, findings=findings)
    if options.enricher is not None:
        report.enrichment, enrich_findings = stage(
            "enrichment", lambda: options.enricher.enrich(extract_iocs(report, include_nested=False), headers.date),
            (None, []))
        report.findings += enrich_findings
    if options.yara_rules is not None:
        report.yara, yara_findings = stage(
            "YARA", lambda: yara_scan.scan(options.yara_rules, raw, tree,
                                           [(tb.part, tb.preview) for tb in body.text_bodies], attachments), ([], []))
        report.findings += yara_findings
    if options.custom_rules:
        report.assessment = assess(report)  # rules may test score/verdict
        rule_findings, report.suppressed = stage(
            "custom rule", lambda: evaluate_rules(options.custom_rules, report, msg), ([], []))
        report.findings += rule_findings
    report.findings += errors
    report.findings.sort(key=lambda f: (-f.severity.rank, f.code))
    report.assessment = assess(report)
    return report


def _analyze_nested(tree, parent: EvidenceInfo, options: AnalysisOptions, depth: int) -> list[NestedReport]:
    out: list[NestedReport] = []
    for leaf in tree.leaves:
        if len(out) >= MAX_NESTED_PER_MESSAGE:
            break
        info, data = leaf.info, leaf.payload
        is_rfc822 = info.content_type in MESSAGE_TYPES
        is_outlook = data.startswith(b"\xd0\xcf\x11\xe0") and (info.filename or "").lower().endswith(".msg") \
            and is_msg(data)
        is_eml_file = (info.filename or "").lower().endswith(".eml")
        if not (is_rfc822 or is_outlook or is_eml_file) or not data:
            continue
        label = f"{parent.path}!{info.path}"
        extra = dict(container=f"{parent.path} part {info.path}", container_sha256=parent.sha256)
        try:
            if is_outlook:
                evidence, raw, msg, msg_info = load_msg_bytes(label, data, **extra)
            else:
                evidence = _info(label, data, "attached", converted=is_rfc822,
                                 notes=["re-serialised from the parent message"] if is_rfc822 else [], **extra)
                raw, msg, msg_info = data, parse_bytes(data), None
        except Exception as exc:  # a broken attachment must not abort the parent analysis
            parent.notes.append(f"attached message {info.path} could not be analysed: {exc}")
            continue
        report = analyze_message(evidence, raw, msg, options, msg_info, depth + 1)
        out.append(NestedReport(part=info.path, filename=info.filename, report=report))
    return out


def _nested_findings(nested: list[NestedReport]) -> list[Finding]:
    out = []
    for n in nested:
        worst = max((f.severity for f in n.report.findings), key=lambda s: s.rank, default=Severity.INFO)
        notable = [f for f in n.report.findings if f.severity.rank >= Severity.MEDIUM.rank]
        subject = n.report.headers.subject or "(no subject)"
        ev = {"part": n.part, "subject": subject, "from": n.report.headers.from_address,
              "sha256": n.report.evidence.sha256, "codes": sorted({f.code for f in notable})[:15]}
        if notable:
            out.append(Finding("NESTED_MESSAGE_SUSPICIOUS", worst,
                               f"Attached message {n.part} ('{subject[:80]}') has {len(notable)} notable finding(s), "
                               f"e.g. {notable[0].code}. See its nested report.", ev))
        else:
            out.append(Finding("NESTED_MESSAGE", Severity.INFO,
                               f"Attached message {n.part} ('{subject[:80]}') was analysed; nothing notable.", ev))
    return out


def _msg_findings(info: MsgInfo) -> list[Finding]:
    ev = {k: v for k, v in vars(info).items() if v}
    out = [Finding("MSG_SOURCE", Severity.INFO,
                   "Input was an Outlook .msg file; MIME was rebuilt from its properties"
                   f"{'' if info.has_transport_headers else ' and it has no original transport headers'}.", ev)]
    if info.last_modified_by:
        out.append(Finding("MSG_LAST_MODIFIED_BY", Severity.INFO,
                           f".msg was last modified by '{info.last_modified_by}' at {info.last_modified_time}.", ev))
    return out

