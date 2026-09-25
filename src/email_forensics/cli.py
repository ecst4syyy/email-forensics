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

    args = parser.parse_args(argv)
    # Evidence may contain undecodable characters; never let printing them crash the run.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    min_rank = Severity(args.min_severity).rank
    exit_code = 0
    outputs = []
    for path in args.files:
        try:
            report = analyze_file(path)
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
