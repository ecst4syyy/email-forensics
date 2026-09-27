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
    exit_code = 0
    outputs = []
    for path in args.files:
        try:
            report = analyze_file(path, extract_dir=args.extract_dir, protected_domains=protected)
        except EvidenceError as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            exit_code = 2
            continue
        report.findings = [f for f in report.findings if f.severity.rank >= min_rank]
        outputs.append(report)

    if args.json:
        if len(outputs) == 1:
            print(to_json(outputs[0]))
        else:
            print(json.dumps([r.to_dict() for r in outputs], indent=2, ensure_ascii=False))
    else:
        print("\n\n".join(to_text(r) for r in outputs))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
