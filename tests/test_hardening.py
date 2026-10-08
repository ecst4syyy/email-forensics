import json
import random
import time
from pathlib import Path

import pytest

from email_forensics import analyzer as analyzer_mod
from email_forensics.analyzer import AnalysisOptions, analyze_message, analyze_path, analyze_with_timeout
from email_forensics.html_analysis import analyze_html, hidden_selectors
from email_forensics.iocs import extract_iocs, to_csv, to_misp, to_stix
from email_forensics.loader import _info, parse_bytes
from email_forensics.report import to_text
from email_forensics.report_html import render_html
import samples as s

FIX = Path(__file__).parent / "fixtures"
REGRESSION = sorted((FIX / "regression").iterdir())


def render_everything(report):
    """Every output path, including strict UTF-8 encoding as used when writing files."""
    for text in (to_text(report), render_html([report]), json.dumps(report.to_dict(), ensure_ascii=False)):
        text.encode("utf-8", "backslashreplace")
    iocs = extract_iocs(report)
    for text in (to_csv(iocs), to_stix(iocs, [report]), to_misp(iocs, [report])):
        text.encode("utf-8")  # strict: IOC files are written as plain UTF-8


def full(raw: bytes, **opts):
    report = analyze_message(_info("t", raw, "eml"), raw, parse_bytes(raw), AnalysisOptions(**opts))
    render_everything(report)
    return report


@pytest.mark.parametrize("path", REGRESSION, ids=[p.name for p in REGRESSION])
def test_regression_corpus(path):
    assert REGRESSION, "regression corpus is empty"
    for report in analyze_path(path):
        render_everything(report)
        assert not [f for f in report.findings if f.code == "ANALYZER_ERROR"], path.name


def test_mutation_fuzz_smoke():
    """A quick deterministic fuzz pass over every fixture; the long runs happen out of band."""
    seeds = [p.read_bytes() for p in sorted(FIX.glob("*.eml"))] + [s.forwarded_eml()]
    rng = random.Random(1234)
    for _ in range(300):
        b = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 20)):
            pos = rng.randrange(len(b) + 1)
            op = rng.random()
            if op < 0.4:
                b[pos:pos] = bytes([rng.choice(b'<>@;()[]"=?\n\r\t :,\\/\xff-')])
            elif op < 0.7 and pos < len(b):
                del b[pos]
            else:
                b[pos:pos] = bytes(rng.randrange(256) for _ in range(3))
        report = full(bytes(b))
        assert not [f for f in report.findings if f.code == "ANALYZER_ERROR"]


def test_stage_isolation(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug in identity analyzer")
    monkeypatch.setattr(analyzer_mod, "analyze_identity", boom)
    report = full((FIX / "phish_html.eml").read_bytes())
    errors = [f for f in report.findings if f.code == "ANALYZER_ERROR"]
    assert errors and errors[0].evidence["stage"] == "identity"
    assert report.body.urls and report.attachments == [] and report.headers.subject  # the rest still ran
    assert report.assessment.verdict == "malicious"


def test_timeout_keeps_message_in_report(monkeypatch):
    def slow(*a, **k):
        while True:
            time.sleep(0.01)
    monkeypatch.setattr(analyzer_mod, "analyze_body", slow)
    raw = (FIX / "legit.eml").read_bytes()
    start = time.time()
    report = analyze_with_timeout(_info("t", raw, "eml"), raw, parse_bytes(raw), AnalysisOptions(timeout=0.3))
    assert time.time() - start < 3
    assert [f.code for f in report.findings] == ["ANALYSIS_TIMEOUT"]
    assert report.headers.subject == "Quarterly report" and report.evidence.sha256


def test_css_class_hiding():
    classes, ids = hidden_selectors(".pre{display:none} #x, .y{font-size:0} "
                                    "@media (max-width:600px){.mobile{display:none!important}} /* .c{display:none} */")
    assert classes == {"pre", "y"} and ids == {"x"}
    html, visible = analyze_html('<style>.hid{display:none}</style><p>seen</p><div class="a hid">secret</div>'
                                 '<div class="mobile">desktop only</div>', "1")
    assert html.hidden_text == ["secret"] and "desktop only" in visible


def test_alternatives_that_differ():
    plain = ("Tomorrow brings sunny mornings, cloudy afternoons and light evening rain across northern valleys; "
             "farmers expect harvest delays while coastal towns prepare festivals near harbour markets")
    html_text = ("Your mailbox password expires today. Verify account credentials immediately using the secure "
                 "portal below, otherwise access will be suspended permanently by administrators")
    raw = (b'Content-Type: multipart/alternative; boundary="B"\n\n--B\nContent-Type: text/plain\n\n'
           + plain.encode() + b'\n--B\nContent-Type: text/html\n\n<p>' + html_text.encode() + b"</p>\n--B--\n")
    assert "BODY_ALTERNATIVES_DIFFER" in {f.code for f in full(raw).findings}
    same = (b'Content-Type: multipart/alternative; boundary="B"\n\n--B\nContent-Type: text/plain\n\n'
            + plain.encode() + b'\n--B\nContent-Type: text/html\n\n<p>' + plain.encode() + b"</p>\n--B--\n")
    assert "BODY_ALTERNATIVES_DIFFER" not in {f.code for f in full(same).findings}


def test_mailbox_performance(tmp_path):
    msgs = [p.read_bytes().replace(b"\r\n", b"\n") for p in sorted(FIX.glob("*.eml"))]
    box = b"".join(b"From MAILER-DAEMON Thu Jan  1 00:00:00 2026\n" + m.rstrip(b"\n") + b"\n\n"
                   for m in msgs * (200 // len(msgs) + 1))[:]
    path = tmp_path / "big.mbox"
    path.write_bytes(box)
    start = time.time()
    reports = list(analyze_path(path))
    elapsed = time.time() - start
    assert len(reports) >= 200 and elapsed < 30, f"{len(reports)} messages took {elapsed:.1f}s"


# --------------------------------------------------------------------------- property-based (optional)

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings, strategies as st  # noqa: E402

from email_forensics.dkimcheck import DkimSyntaxError, parse_tags  # noqa: E402
from email_forensics.headers import parse_authentication_results, parse_received  # noqa: E402
from email_forensics.lookalike import build_protected, check_host, skeleton  # noqa: E402
from email_forensics.mime import decode_text  # noqa: E402
from email_forensics.report_html import defang, esc  # noqa: E402
from email_forensics.textcheck import safe_display  # noqa: E402
from email_forensics.urls import extract_text_urls, split_url  # noqa: E402

FAST = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
PROTECTED = build_protected({"acme-corp.com"})


@FAST
@given(st.text(max_size=300))
def test_header_parsers_never_raise(text):
    parse_received(text)
    parse_authentication_results(text)
    split_url(text)
    extract_text_urls(text, "1")
    check_host(text, PROTECTED, "X")
    skeleton(text)


@FAST
@given(st.text(max_size=200))
def test_dkim_tag_parser_raises_only_syntax_errors(text):
    try:
        parse_tags(text)
    except DkimSyntaxError:
        pass


@FAST
@given(st.binary(max_size=300), st.text(max_size=20))
def test_decode_text_never_raises(data, charset):
    text, _ = decode_text(data, charset)
    assert isinstance(text, str)


@FAST
@given(st.text(max_size=300))
def test_html_output_is_always_inert(text):
    out = esc(text)
    assert "<" not in out and ">" not in out and '"' not in out
    assert "http://" not in out.lower() and "https://" not in out.lower()
    assert "‮" not in safe_display(text) and "​" not in safe_display(text)
    assert "://" not in defang("http://" + text) or defang("http://" + text).startswith("hxxp://")


@FAST
@given(st.text(max_size=2000))
def test_html_analyzer_never_raises(text):
    analyze_html(text, "1")
