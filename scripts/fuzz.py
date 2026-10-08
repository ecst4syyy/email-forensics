"""Mutation fuzzer for the whole analysis pipeline.

Mutates the test fixtures (emails, .msg files, Office/PDF/LNK/OneNote payloads
inside emails) and runs the full analysis plus all report renderers on each
input. Any exception or ANALYZER_ERROR is a bug: the input is saved to --crashes
so it can be added to tests/fixtures/regression/.

    python scripts/fuzz.py --iterations 20000 --seed 1
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import samples  # noqa: E402
from email_forensics.analyzer import AnalysisOptions, analyze_message  # noqa: E402
from email_forensics.custom_rules import load_rules  # noqa: E402
from email_forensics.iocs import extract_iocs, to_csv, to_misp, to_stix  # noqa: E402
from email_forensics.loader import EvidenceError, _info, load_msg_bytes, parse_bytes  # noqa: E402
from email_forensics.report import to_text  # noqa: E402
from email_forensics.report_html import render_html  # noqa: E402
from email_forensics.resolver import RecordingResolver, ReplayResolver  # noqa: E402


def seeds() -> list[tuple[str, bytes]]:
    out = [(p.name, p.read_bytes()) for p in sorted((ROOT / "tests" / "fixtures").rglob("*.eml"))]
    out += [("phish.msg", samples.phish_msg()), ("sent.msg", samples.sent_item_msg())]
    out.append(("payloads.eml", samples.message_with([
        ("a.docm", "application/octet-stream", samples.malicious_docm()),
        ("b.pdf", "application/pdf", samples.malicious_pdf()),
        ("c.lnk", "application/octet-stream", samples.malicious_lnk()),
        ("d.one", "application/octet-stream", samples.malicious_onenote()),
        ("e.doc", "application/msword", samples.malicious_doc()),
        ("f.rtf", "application/rtf", samples.equation_rtf()),
        ("g.zip", "application/zip", samples.make_zip({"x/y.exe": samples.fake_pe()}))])))
    out.append(("forwarded.eml", samples.forwarded_eml()))
    return out


def mutate(data: bytes, rng: random.Random) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 16)):
        if not b:
            break
        pos = rng.randrange(len(b))
        r = rng.random()
        if r < 0.35:
            b[pos] = rng.randrange(256)
        elif r < 0.55:
            b[pos:pos] = bytes([rng.choice(b'<>@;()[]"=?\n\r\t :,\\/-*\'.%#&{}')])
        elif r < 0.7:
            b[pos:pos + 4] = rng.choice([b"\xff\xff\xff\xff", b"\x00\x00\x00\x00", b"\xfe\xff\xff\xff", b"\x10\x00\x00\x00"])
        elif r < 0.85:
            del b[pos:pos + rng.randint(1, 64)]
        else:  # duplicate a chunk (repeated headers, parts, records)
            n = rng.randint(1, 200)
            b[pos:pos] = b[pos:pos + n]
    return bytes(b)


def run_one(name: str, data: bytes, options: AnalysisOptions):
    if name.endswith(".msg"):
        try:
            evidence, raw, msg, info = load_msg_bytes(name, data)
        except EvidenceError:
            return None
        report = analyze_message(evidence, raw, msg, options, info)
    else:
        report = analyze_message(_info(name, data, "eml"), data, parse_bytes(data), options)
    for text in (to_text(report), render_html([report]), json.dumps(report.to_dict(), ensure_ascii=False)):
        text.encode("utf-8", "backslashreplace")  # how the CLI writes reports
    iocs = extract_iocs(report)
    for text in (to_csv(iocs), to_stix(iocs, [report]), to_misp(iocs, [report])):
        text.encode("utf-8")  # IOC files are strict UTF-8
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iterations", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--crashes", default="fuzz-crashes")
    args = ap.parse_args()

    options = AnalysisOptions(
        resolver=RecordingResolver(ReplayResolver(ROOT / "tests" / "fixtures" / "dkim" / "dns.json")),
        custom_rules=load_rules([ROOT / "examples" / "rules" / "example.toml"]))
    try:
        from email_forensics.yara_scan import compile_rules
        options.yara_rules = compile_rules([ROOT / "examples" / "yara"])
    except Exception:  # yara-python not installed
        pass

    rng = random.Random(args.seed)
    corpus = seeds()
    crashes = Path(args.crashes)
    failures, worst, start = 0, (0.0, ""), time.time()
    for i in range(args.iterations):
        name, data = rng.choice(corpus)
        mutated = mutate(data, rng)
        t = time.time()
        try:
            report = run_one(name, mutated, options)
            problem = report and next((f for f in report.findings if f.code == "ANALYZER_ERROR"), None)
            if problem:
                raise RuntimeError(problem.evidence.get("error"))
        except Exception:
            failures += 1
            crashes.mkdir(exist_ok=True)
            out = crashes / f"crash-{args.seed}-{i}-{name}"
            out.write_bytes(mutated)
            if failures <= 3:
                print(f"--- {out}", file=sys.stderr)
                traceback.print_exc()
        dt = time.time() - t
        if dt > worst[0]:
            worst = (dt, name)
    print(f"{args.iterations} inputs, {failures} failures, slowest {worst[0]:.2f}s ({worst[1]}), "
          f"total {time.time() - start:.0f}s")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
