"""Command-line interface: ``email-forensics analyze message.eml``."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .analyzer import analyze_file
from .loader import EvidenceError
from .models import Severity
from .report import to_json, to_text
from .resolver import DohResolver, RecordingResolver, ReplayResolver, SystemResolver


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="email-forensics", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="analyze one or more .eml files")
    analyze.add_argument("files", nargs="+")
    analyze.add_argument("--json", action="store_true", help="output JSON instead of text")
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
    for path in args.files:
        try:
            report = analyze_file(path, extract_dir=args.extract_dir, protected_domains=protected,
                                  resolver=resolver, spf_ip=args.spf_ip)
        except EvidenceError as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            exit_code = 2
            continue
        report.findings = [f for f in report.findings if f.severity.rank >= min_rank]
        outputs.append(report)

    if resolver is not None and args.dns_record:
        resolver.save(args.dns_record)

    if args.json:
        if len(outputs) == 1:
            print(to_json(outputs[0]))
        else:
            print(json.dumps([r.to_dict() for r in outputs], indent=2, ensure_ascii=False))
    else:
        print("\n\n".join(to_text(r) for r in outputs))
    return exit_code


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
