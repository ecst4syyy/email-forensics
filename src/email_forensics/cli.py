"""Command-line interface.

    email-forensics analyze message.eml|message.msg|mailbox.mbox [options]
    email-forensics case init|add|analyze|report|search|verify|log CASE_DIR ...
    email-forensics verify-signature REPORT [--public-key HEX]
    email-forensics serve [--host 127.0.0.1] [--port 8025]
    email-forensics watch INBOX_DIR --output-dir OUT_DIR [--once]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .analyzer import AnalysisOptions, analyze_path
from .case import Case, CaseError, verify_signature
from .custom_rules import RuleError, load_rules
from .enrich import Enricher, HttpFetcher, Recorder, ReplayFetcher
from .iocs import extract_iocs, to_csv, to_misp, to_stix
from .loader import EvidenceError
from .models import Severity
from .report import summary_row, to_json, to_summary, to_text
from .report_html import render_html
from .siem import to_cef, to_jsonl
from .resolver import DohResolver, RecordingResolver, ReplayResolver, SystemResolver
from .yara_scan import YaraUnavailable
from .yara_scan import compile_rules as compile_yara


class UsageError(Exception):
    pass


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    # Evidence may contain undecodable characters; never let printing them crash the run.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    try:
        if args.command == "analyze":
            return _cmd_analyze(args)
        if args.command == "case":
            return _cmd_case(args)
        if args.command == "verify-signature":
            ok = verify_signature(args.file, args.signature, args.public_key)
            print(f"{'valid' if ok else 'INVALID'} signature for {args.file}")
            return 0 if ok else 1
        if args.command == "serve":
            return _cmd_serve(args)
        if args.command == "watch":
            return _cmd_watch(args)
    except (UsageError, CaseError, RuleError, YaraUnavailable, ValueError, OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


# --------------------------------------------------------------------------- argument parsing


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="email-forensics", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="analyze .eml, .msg or mbox files")
    analyze.add_argument("files", nargs="+")
    analyze.add_argument("--format", choices=["text", "json", "html", "jsonl", "cef"], default="text",
                         help="report format (jsonl/cef: one SIEM event per message)")
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
    analyze.add_argument("--extract-dir", metavar="DIR",
                         help="write attachments to DIR as read-only <sha256>.bin files with a manifest.json")
    add_analysis_arguments(analyze)

    case = sub.add_parser("case", help="manage an investigation case (evidence, custody, reports, search)")
    csub = case.add_subparsers(dest="case_command", required=True)
    c_init = csub.add_parser("init", help="create a case directory")
    c_init.add_argument("dir")
    c_init.add_argument("--name", required=True)
    c_init.add_argument("--examiner")
    c_init.add_argument("--no-signing-key", action="store_true", help="do not create an Ed25519 signing key")
    c_init.add_argument("--key", metavar="FILE", help="store the private signing key here instead of in the case")
    c_add = csub.add_parser("add", help="copy evidence into the case (read-only) and log it")
    c_add.add_argument("dir")
    c_add.add_argument("files", nargs="+")
    c_add.add_argument("--note", help="where the evidence came from, ticket number, ...")
    c_add.add_argument("--examiner")
    c_an = csub.add_parser("analyze", help="analyze new evidence and write signed reports")
    c_an.add_argument("dir")
    c_an.add_argument("--all", action="store_true", help="re-analyze evidence that already has reports")
    c_an.add_argument("--examiner")
    add_analysis_arguments(c_an)
    c_rep = csub.add_parser("report", help="write case-report.html and iocs.csv")
    c_rep.add_argument("dir")
    c_rep.add_argument("--examiner")
    c_search = csub.add_parser("search", help="find an indicator, sender or subject across the case")
    c_search.add_argument("dir")
    c_search.add_argument("query")
    c_search.add_argument("--type", help="only this indicator type (domain, url, ipv4, sha256, email-addr, ...)")
    c_search.add_argument("--json", action="store_true")
    c_verify = csub.add_parser("verify", help="verify the custody chain, evidence hashes and report signatures")
    c_verify.add_argument("dir")
    c_log = csub.add_parser("log", help="print the chain-of-custody log")
    c_log.add_argument("dir")
    c_log.add_argument("--json", action="store_true")

    vs = sub.add_parser("verify-signature", help="verify a signed report (e.g. one received from another examiner)")
    vs.add_argument("file")
    vs.add_argument("--signature", help="signature file (default: FILE.sig)")
    vs.add_argument("--public-key", help="expected public key (hex); default: the key named in the signature")

    serve = sub.add_parser("serve", help="run the local REST API and upload page")
    serve.add_argument("--host", default="127.0.0.1",
                       help="address to listen on (default %(default)s; others need an API token)")
    serve.add_argument("--port", type=int, default=8025)
    serve.add_argument("--max-upload", metavar="MB", type=float, default=50, help="largest accepted upload (MB)")
    serve.add_argument("--token-file", metavar="FILE",
                       help="read the API token from FILE (default: the EMAIL_FORENSICS_API_TOKEN variable)")
    serve.add_argument("--quiet", action="store_true", help="do not log requests")
    add_analysis_arguments(serve)

    watch = sub.add_parser("watch", help="analyze every new file dropped into a folder")
    watch.add_argument("inbox")
    watch.add_argument("--output-dir", required=True, metavar="DIR",
                       help="reports, events.jsonl and the processed-file list go here")
    watch.add_argument("--report-format", choices=["json", "html", "text", "none"], default="json")
    watch.add_argument("--interval", type=float, default=5.0, help="seconds between polls (default %(default)s)")
    watch.add_argument("--once", action="store_true", help="process what is there now and exit")
    watch.add_argument("--all-files", action="store_true", help="consider every file, not just .eml/.msg/.mbox")
    add_analysis_arguments(watch)
    return parser


def add_analysis_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--protected-domain", metavar="DOMAIN", action="append", default=[],
                   help="your own or a partner domain to watch for lookalikes (repeatable)")
    p.add_argument("--protected-domains-file", metavar="FILE",
                   help="file with one protected domain per line (# comments allowed)")
    p.add_argument("--timeout", metavar="SECONDS", type=float,
                   help="give up on a message after SECONDS (it is still reported, as incomplete)")
    p.add_argument("--max-nesting", metavar="N", type=int, default=3,
                   help="analyse attached emails up to N levels deep (default %(default)s)")
    p.add_argument("--yara", metavar="PATH", action="append", default=[],
                   help="YARA rule file or directory (repeatable; needs yara-python)")
    p.add_argument("--rules", metavar="FILE", action="append", default=[],
                   help="custom detection/suppression rules, JSON or TOML (repeatable)")
    online = p.add_argument_group("authentication re-verification (DNS lookups are opt-in)")
    online.add_argument("--online", action="store_true",
                        help="verify DKIM/ARC signatures, SPF and DMARC using system DNS (needs dnspython)")
    online.add_argument("--doh", action="store_true",
                        help="like --online, but over DNS-over-HTTPS (stdlib only; see --doh-url)")
    online.add_argument("--doh-url", metavar="URL",
                        help="DNS-over-HTTPS JSON endpoint; implies --doh (default https://dns.google/resolve)")
    online.add_argument("--dns-replay", metavar="FILE", help="answer DNS only from a recording (offline, reproducible)")
    online.add_argument("--dns-record", metavar="FILE", help="save every DNS lookup made to FILE for later --dns-replay")
    online.add_argument("--spf-ip", metavar="IP", help="connecting IP to evaluate SPF for (default: from headers)")
    enrich = p.add_argument_group("enrichment (opt-in; sends indicators to third parties, never files)")
    enrich.add_argument("--enrich", action="store_true",
                        help="look up indicators: RDAP always, Team Cymru ASN with DNS enabled, and VirusTotal / "
                             "URLhaus / MalwareBazaar / AbuseIPDB when VT_API_KEY / ABUSE_CH_API_KEY / "
                             "ABUSEIPDB_API_KEY are set")
    enrich.add_argument("--enrich-providers", metavar="LIST",
                        help="comma-separated subset: cymru,rdap,virustotal,urlhaus,malwarebazaar,abuseipdb")
    enrich.add_argument("--enrich-cache", metavar="DIR", default=str(Path.home() / ".cache" / "email-forensics"),
                        help="cache answers here for 24h (default %(default)s); --no-enrich-cache disables")
    enrich.add_argument("--no-enrich-cache", action="store_true", help="do not read or write the cache")
    enrich.add_argument("--enrich-record", metavar="FILE", help="save every enrichment request/answer to FILE")
    enrich.add_argument("--enrich-replay", metavar="FILE", help="answer enrichment only from a recording (offline)")


def build_options(args, extract_dir: str | None = None) -> AnalysisOptions:
    protected = list(args.protected_domain)
    if args.protected_domains_file:
        with open(args.protected_domains_file, encoding="utf-8") as fh:
            protected += [line.split("#", 1)[0].strip() for line in fh if line.split("#", 1)[0].strip()]
    resolver = _make_resolver(args)
    return AnalysisOptions(
        extract_dir=extract_dir, protected_domains=protected, resolver=resolver, spf_ip=args.spf_ip,
        enricher=_make_enricher(args, resolver), yara_rules=compile_yara(args.yara) if args.yara else None,
        custom_rules=load_rules(args.rules) if args.rules else [], timeout=args.timeout,
        max_nested_depth=max(0, args.max_nesting))


def save_recordings(args, options: AnalysisOptions) -> None:
    if options.resolver is not None and args.dns_record:
        options.resolver.save(args.dns_record)
    if options.enricher is not None and args.enrich_record:
        options.enricher.fetcher.save(args.enrich_record)


# --------------------------------------------------------------------------- analyze


def _cmd_analyze(args) -> int:
    options = build_options(args, args.extract_dir)
    min_rank = Severity(args.min_severity).rank
    exit_code = 0
    outputs = []
    for path in args.files:
        try:
            for report in analyze_path(path, options):
                _filter(report, min_rank)
                outputs.append(report)
        except (EvidenceError, OSError) as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            exit_code = 2
    save_recordings(args, options)

    fmt = "json" if args.json else args.format
    if args.summary:
        text = (json.dumps([summary_row(r) for r in outputs], indent=2, ensure_ascii=False) if fmt == "json"
                else to_summary(outputs))
    elif fmt == "html":
        text = render_html(outputs) if outputs else ""
    elif fmt == "json":
        text = to_json(outputs[0]) if len(outputs) == 1 else json.dumps([r.to_dict() for r in outputs],
                                                                         indent=2, ensure_ascii=False)
    elif fmt == "jsonl":
        text = to_jsonl(outputs)
    elif fmt == "cef":
        text = to_cef(outputs)
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


# --------------------------------------------------------------------------- case


def _cmd_case(args) -> int:
    cmd = args.case_command
    if cmd == "init":
        case = Case.init(args.dir, args.name, args.examiner, signing_key=not args.no_signing_key, key_path=args.key)
        print(f"created case '{args.name}' ({case.meta['id']}) in {args.dir}")
        if case.meta.get("public_key"):
            print(f"report signing key: {case.meta['key_path']} (keep it private)")
            print(f"public key: {case.meta['public_key']}")
        return 0
    case = Case(args.dir)
    if cmd == "add":
        code = 0
        for f in args.files:
            try:
                item = case.add(f, args.examiner, args.note)
                print(f"added {f} as {item['stored_as']} ({item['format']})")
            except CaseError as exc:
                print(f"error: {exc}", file=sys.stderr)
                code = 2
        return code
    if cmd == "analyze":
        options = build_options(args)
        reports = case.analyze(options, args.examiner, only_new=not args.all)
        save_recordings(args, options)
        print(to_summary(reports) if reports else "nothing new to analyze (use --all to re-analyze)")
        return 0
    if cmd == "report":
        result = case.build_report(args.examiner)
        print(f"wrote case-report.html and iocs.csv ({result['messages']} message(s), "
              f"{result['indicators']} indicator(s))")
        return 0
    if cmd == "search":
        hits = case.search(args.query, args.type)
        if args.json:
            print(json.dumps(hits, indent=2, ensure_ascii=False))
        else:
            for h in hits:
                print(f"{h['message_sha256'][:16]}  {h['verdict'] or '-':<10}  {h['match']:<28}  {h['value'][:70]}"
                      f"  | {(h['subject'] or '')[:40]}")
            print(f"{len(hits)} match(es)")
        return 0
    if cmd == "verify":
        result = case.verify()
        for p in result.problems:
            print(f"PROBLEM [{p.kind}] {p.detail}")
        print(f"{'OK' if result.ok else 'FAILED'}: {result.entries} custody entries, {result.evidence} evidence "
              f"file(s), {result.reports} report file(s) checked")
        return 0 if result.ok else 1
    if cmd == "log":
        entries = case.entries()
        if args.json:
            print(json.dumps(entries, indent=2, ensure_ascii=False))
        else:
            for e in entries:
                d = e["details"]
                what = d.get("original_path") or d.get("message") or d.get("name") or ", ".join(d.get("files", {}))
                print(f"{e['seq']:>4}  {e['time'][:19]}  {e['examiner']:<12}  {e['action']:<15}  {what}"
                      f"{'  [signed]' if e.get('signature') else ''}")
        return 0
    raise UsageError(f"unknown case command {cmd}")


# --------------------------------------------------------------------------- serve / watch


def _cmd_serve(args) -> int:
    from .server import TOKEN_ENV, ForensicsServer

    if args.token_file:
        with open(args.token_file, encoding="utf-8") as fh:
            token = fh.read().strip()
    else:
        token = os.environ.get(TOKEN_ENV) or None
    options = build_options(args)
    server = ForensicsServer((args.host, args.port), options, token=token,
                             max_upload=int(args.max_upload * 1024 * 1024), quiet=args.quiet)
    host = f"[{args.host}]" if ":" in args.host else args.host
    print(f"email-forensics API on http://{host}:{server.server_address[1]}/"
          f"{' (token required)' if token else ''}; Ctrl-C to stop", file=sys.stderr)
    try:
        server.serve()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        save_recordings(args, options)
    return 0


def _cmd_watch(args) -> int:
    from .watch import Watcher

    def report(path, reports, error):
        if error:
            print(f"error: {path.name}: {error}", file=sys.stderr)
        for r in reports:
            a = r.assessment
            print(f"{path.name}: {a.verdict if a else '?'} ({a.score if a else '?'}) {r.headers.subject or ''}"[:160],
                  flush=True)

    options = build_options(args)
    watcher = Watcher(args.inbox, args.output_dir, options, args.report_format, all_files=args.all_files,
                      on_report=report)
    if not args.once:
        print(f"watching {args.inbox} every {args.interval:g}s; Ctrl-C to stop", file=sys.stderr)
    watcher.run(args.interval, once=args.once)
    save_recordings(args, options)
    return 0


# --------------------------------------------------------------------------- helpers


def _make_enricher(args, resolver) -> Enricher | None:
    if not (args.enrich or args.enrich_replay):
        if args.enrich_record or args.enrich_providers:
            raise UsageError("--enrich-record/--enrich-providers need --enrich")
        return None
    fetcher = ReplayFetcher(args.enrich_replay) if args.enrich_replay else HttpFetcher()
    cache = None if (args.no_enrich_cache or args.enrich_replay) else Path(args.enrich_cache) / "enrich"
    providers = [p.strip() for p in args.enrich_providers.split(",") if p.strip()] if args.enrich_providers else None
    return Enricher(Recorder(fetcher, cache), resolver=resolver, providers=providers)


def _make_resolver(args) -> RecordingResolver | None:
    doh = args.doh or bool(args.doh_url)
    chosen = [flag for flag, on in (("--online", args.online), ("--doh", doh), ("--dns-replay", args.dns_replay)) if on]
    if len(chosen) > 1:
        raise UsageError(f"choose one of {', '.join(chosen)}")
    if args.dns_replay:
        return RecordingResolver(ReplayResolver(args.dns_replay))
    if doh:
        return RecordingResolver(DohResolver(args.doh_url or "https://dns.google/resolve"))
    if args.online:
        return RecordingResolver(SystemResolver())
    if args.dns_record:
        raise UsageError("--dns-record needs --online, --doh or --dns-replay")
    return None


if __name__ == "__main__":
    sys.exit(main())
