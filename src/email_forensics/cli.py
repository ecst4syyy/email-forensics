"""Command-line interface: ``email-forensics analyze message.eml|message.msg|mailbox.mbox``."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .analyzer import AnalysisOptions, analyze_path
from .loader import EvidenceError
from .models import Severity
from .iocs import extract_iocs, to_csv, to_misp, to_stix
from .report import summary_row, to_json, to_summary, to_text
from .report_html import render_html
from .resolver import DohResolver, RecordingResolver, ReplayResolver, SystemResolver


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="email-forensics", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="analyze .eml, .msg or mbox files")
    analyze.add_argument("files", nargs="+")
    analyze.add_argument("--format", choices=["text", "json", "html"], default="text", help="report format")
    analyze.add_argument("--json", action="store_true", help="same as --format json")
    analyze.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    analyze.add_argument("--iocs", metavar="FILE", help="also export indicators to FILE")
    analyze.add_argument("--ioc-format", choices=["csv", "stix", "misp"],
                         help="indicator format (default: csv for .csv files, otherwise stix)")
    analyze.add_argument("--fail-on", choices=["caution", "suspicious", "malicious"],
                         help="exit with status 1 if any message reaches this verdict (for automation)")
    analyze.add_argument("--summary", action="store_true",
                         help="one line per message instead of full reports (useful for mailboxes)")
    analyze.add_argument("--min-severity", choices=[s.value for s in Severity], default="info",
                         help="hide findings below this severity")
    analyze.add_argument("--protected-domain", metavar="DOMAIN", action="append", default=[],
                         help="your own or a partner domain to watch for lookalikes (repeatable)")
    analyze.add_argument("--protected-domains-file", metavar="FILE",
                         help="file with one protected domain per line (# comments allowed)")
    online = analyze.add_argument_group("authentication re-verification (DNS lookups are opt-in)")
    online.add_argument("--online", action="store_true",
                        help="verify DKIM/ARC signatures, SPF and DMARC using system DNS (needs dnspython)")
    online.add_argument("--doh", action="store_true",
                        help="like --online, but over DNS-over-HTTPS (stdlib only; see --doh-url)")
    online.add_argument("--doh-url", metavar="URL",
                        help="DNS-over-HTTPS JSON endpoint; implies --doh (default https://dns.google/resolve)")
    online.add_argument("--dns-replay", metavar="FILE", help="answer DNS only from a recording (offline, reproducible)")
    online.add_argument("--dns-record", metavar="FILE", help="save every DNS lookup made to FILE for later --dns-replay")
    online.add_argument("--spf-ip", metavar="IP", help="connecting IP to evaluate SPF for (default: from headers)")
    analyze.add_argument("--extract-dir", metavar="DIR",
                         help="write attachments to DIR as read-only <sha256>.bin files with a manifest.json")

    args = parser.parse_args(argv)
    # Evidence may contain undecodable characters; never let printing them crash the run.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    min_rank = Severity(args.min_severity).rank
    protected = list(args.protected_domain)
    if args.protected_domains_file:
        try:
            with open(args.protected_domains_file, encoding="utf-8") as fh:
                protected += [line.split("#", 1)[0].strip() for line in fh if line.split("#", 1)[0].strip()]
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    try:
        resolver = _make_resolver(args)
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    exit_code = 0
    outputs = []
    options = AnalysisOptions(extract_dir=args.extract_dir, protected_domains=protected,
                              resolver=resolver, spf_ip=args.spf_ip)
    for path in args.files:
        try:
            for report in analyze_path(path, options):
                _filter(report, min_rank)
                outputs.append(report)
        except (EvidenceError, OSError) as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            exit_code = 2
            continue

    if resolver is not None and args.dns_record:
        resolver.save(args.dns_record)

    fmt = "json" if args.json else args.format
    if args.summary:
        text = (json.dumps([summary_row(r) for r in outputs], indent=2, ensure_ascii=False) if fmt == "json"
                else to_summary(outputs))
    elif fmt == "html":
        text = render_html(outputs) if outputs else ""
    elif fmt == "json":
        text = to_json(outputs[0]) if len(outputs) == 1 else json.dumps([r.to_dict() for r in outputs],
                                                                         indent=2, ensure_ascii=False)
    else:
        text = "\n\n".join(to_text(r) for r in outputs)
    if args.output:
        with open(args.output, "w", encoding="utf-8", errors="backslashreplace") as fh:
            fh.write(text + "\n")
    else:
        print(text)

    if args.iocs and outputs:
        indicators = [i for r in outputs for i in extract_iocs(r)]
        kind = args.ioc_format or ("csv" if args.iocs.lower().endswith(".csv") else "stix")
        data = {"csv": lambda: to_csv(indicators), "stix": lambda: to_stix(indicators, outputs),
                "misp": lambda: to_misp(indicators, outputs)}[kind]()
        with open(args.iocs, "w", encoding="utf-8", newline="") as fh:
            fh.write(data)

    if args.fail_on and exit_code == 0:
        order = ["clean", "caution", "suspicious", "malicious"]
        threshold = order.index(args.fail_on)
        if any(r.assessment and order.index(r.assessment.verdict) >= threshold for r in outputs):
            return 1
    return exit_code


def _filter(report, min_rank: int) -> None:
    report.findings = [f for f in report.findings if f.severity.rank >= min_rank]
    for nested in report.nested:
        _filter(nested.report, min_rank)


def _make_resolver(args) -> RecordingResolver | None:
    doh = args.doh or bool(args.doh_url)
    chosen = [flag for flag, on in (("--online", args.online), ("--doh", doh), ("--dns-replay", args.dns_replay)) if on]
    if len(chosen) > 1:
        raise ValueError(f"choose one of {', '.join(chosen)}")
    if args.dns_replay:
        return RecordingResolver(ReplayResolver(args.dns_replay))
    if doh:
        return RecordingResolver(DohResolver(args.doh_url or "https://dns.google/resolve"))
    if args.online:
        return RecordingResolver(SystemResolver())
    if args.dns_record:
        raise ValueError("--dns-record needs --online, --doh or --dns-replay")
    return None


if __name__ == "__main__":
    sys.exit(main())
