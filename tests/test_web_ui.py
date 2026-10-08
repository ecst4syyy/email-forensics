"""End-to-end tests of the web UI in a real browser (Playwright + Chromium).

Skipped when Playwright or a Chromium build is not available. Locally:
    pip install playwright && playwright install chromium
Set EF_CHROMIUM to use a specific browser binary.
"""

import csv
import io
import json
import os
import threading
from pathlib import Path

import pytest

from email_forensics.analyzer import AnalysisOptions
from email_forensics.server import ForensicsServer
import samples

sync_api = pytest.importorskip("playwright.sync_api")

FIX = Path(__file__).parent / "fixtures"
PHISH = (FIX / "phish_html.eml").read_bytes()
LEGIT = (FIX / "legit.eml").read_bytes()
BEC = (FIX / "bec_spoof.eml").read_bytes()
TOKEN = "web-ui-test-token-0123456789"
UNICODE_NAME = "Gaurav, your Fitness Nation Bedford account – payment due.eml"


def _executable() -> str | None:
    for candidate in (os.environ.get("EF_CHROMIUM"), "/opt/pw-browsers/chromium"):
        if candidate and Path(candidate).exists():
            return candidate
    return None


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch(executable_path=_executable(), args=["--no-proxy-server"])
        except Exception as exc:  # no browser installed
            pytest.skip(f"Chromium not available: {exc}")
        yield b
        b.close()


@pytest.fixture
def server():
    servers = []

    def start(**kw):
        kw.setdefault("quiet", True)
        srv = ForensicsServer(("127.0.0.1", 0), kw.pop("options", None) or AnalysisOptions(), **kw)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}/"

    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


@pytest.fixture
def page(browser):
    """A page that fails the test on any JavaScript error, console error or CSP violation."""
    problems = []
    ctx = browser.new_context(viewport={"width": 1440, "height": 1000}, accept_downloads=True)
    pg = ctx.new_page()
    pg.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
    pg.on("console", lambda m: problems.append(f"console {m.type}: {m.text}") if m.type == "error" else None)
    pg.on("dialog", lambda d: (problems.append(f"dialog: {d.message}"), d.dismiss()))
    pg.problems = problems
    yield pg
    ctx.close()
    expected = [p for p in problems if "401" in p or "422" in p or "413" in p]  # failed fetches we provoke
    assert [p for p in problems if p not in expected] == []


def open_app(pg, base):
    pg.goto(base)
    pg.locator("#version", has_text="v1").wait_for()


def upload(pg, tmp_path, files: dict[str, bytes]):
    paths = []
    for name, data in files.items():
        path = tmp_path / name
        path.write_bytes(data)
        paths.append(str(path))
    pg.set_input_files("#file-input", paths)


def wait_done(pg, count):
    pg.locator(".history-item:not(.pending)").nth(count - 1).wait_for(timeout=30000)
    pg.locator(".history-item.pending").first.wait_for(state="detached", timeout=30000)


def tab(pg, name):
    pg.locator(".tab", has_text=name).click()
    return pg.locator("#tab-body")


# --------------------------------------------------------------------------- uploads


def test_unicode_file_name_from_the_bug_report(page, server, tmp_path):
    base = server()
    open_app(page, base)
    upload(page, tmp_path, {UNICODE_NAME: BEC, "Rechnung über 500 € 🧾.eml": PHISH})
    wait_done(page, 2)
    assert page.locator(".history-item.failed").count() == 0
    assert page.locator(".history-item", has_text="Fitness Nation Bedford").count() == 1
    page.locator(".history-item", has_text="Fitness Nation Bedford").click()
    raw = tab(page, "Raw JSON").locator("pre").text_content()
    assert json.loads(raw)["evidence"]["path"] == f"upload:{UNICODE_NAME}"


def test_multiple_files_mbox_msg_and_selection(page, server, tmp_path):
    base = server()
    open_app(page, base)
    box = b"".join(b"From MAILER-DAEMON Thu Jan  1 00:00:00 2026\n" + m.replace(b"\r\n", b"\n") + b"\n"
                   for m in (LEGIT, BEC, PHISH))
    upload(page, tmp_path, {"export.mbox": box, "reported.msg": samples.phish_msg(), "a.eml": PHISH})
    wait_done(page, 5)  # three mailbox messages, one .msg, one .eml
    assert page.locator(".history-item").count() == 5
    assert page.locator(".history-item", has_text="export.mbox · #3").count() == 1
    # the message the user picks stays on screen
    page.locator(".history-item", has_text="Quarterly report").click()
    assert page.locator(".hero-subject").text_content() == "Quarterly report"
    assert page.locator(".verdict-pill").text_content() == "clean"
    page.locator(".history-item", has_text="reported.msg").click()
    assert "converted from Outlook .msg" in page.locator("#report").text_content()


def test_drag_and_drop(page, server):
    base = server()
    open_app(page, base)
    dt = page.evaluate_handle("""(bytes) => {
        const dt = new DataTransfer();
        dt.items.add(new File([new Uint8Array(bytes)], "dropped.eml", { type: "message/rfc822" }));
        return dt;
    }""", list(PHISH))
    page.dispatch_event("#dropzone", "dragenter", {"dataTransfer": dt})
    assert "drag" in page.locator("#dropzone").get_attribute("class")
    page.dispatch_event("#dropzone", "drop", {"dataTransfer": dt})
    page.locator(".hero").wait_for()
    assert page.locator(".verdict-pill").text_content() == "malicious"
    assert "drag" not in page.locator("#dropzone").get_attribute("class")


# --------------------------------------------------------------------------- report views


def test_overview_and_every_tab(page, server, tmp_path):
    base = server(options=AnalysisOptions(protected_domains=["recipient.net"]))
    open_app(page, base)
    upload(page, tmp_path, {"phish.eml": PHISH})
    page.locator(".hero").wait_for()
    assert page.locator(".gauge-score").text_content().isdigit()
    assert page.locator(".verdict-pill").text_content() == "malicious"
    assert page.locator(".reason").count() >= 5
    assert page.locator(".bar-row").count() >= 2
    assert page.locator(".stat").count() == 4

    findings = tab(page, "Findings")
    n = page.locator(".finding").count()
    assert n == int(page.locator(".tab", has_text="Findings").locator(".count").text_content())
    page.locator(".filter", has_text="High").click()
    assert 0 < page.locator(".finding").count() < n
    assert page.locator(".finding .sev-high").count() == page.locator(".finding").count()
    page.locator(".filter", has_text="All").click()
    page.fill(".search", "lookalike_combo")
    assert page.locator(".finding").count() >= 1
    assert all("LOOKALIKE_COMBO" in t for t in page.locator(".finding .f-code").all_text_contents())
    page.fill(".search", "zzz-no-such-finding")
    assert "No findings match" in findings.text_content()
    page.fill(".search", "")
    page.locator(".finding summary").first.click()
    assert page.locator(".finding[open] .finding-body pre").count() == 1

    route = tab(page, "Sender & route").text_content()
    assert "secure-paypa1.com" in route and "origin IP" in route and "mx.recipient.net" in route

    auth = tab(page, "Authentication").text_content()
    assert "Offline mode" in auth and "Recorded by the receiving server" in auth
    assert page.locator("#tab-body .res-pass").count() >= 1

    links = tab(page, "Links & content")
    assert page.locator("#tab-body tbody tr").count() == 9
    text = links.text_content()
    assert "hxxp" in text and "[.]" in text and "flagged" in text
    assert page.locator("#tab-body a[href]").count() == 0  # nothing from the email is clickable
    assert "Hidden from the reader" in text and "What the reader sees" in text

    assert "No attachments" in tab(page, "Attachments").text_content()

    tab(page, "Indicators")
    total = page.locator("#tab-body tbody tr").count()
    assert total > 10
    page.locator("#tab-body .filter", has_text="domain").click()
    assert 0 < page.locator("#tab-body tbody tr").count() < total
    assert all(c == "domain" for c in page.locator("#tab-body tbody tr td:first-child").all_text_contents())

    raw = tab(page, "Raw JSON").locator("pre").text_content()
    assert json.loads(raw)["assessment"]["verdict"] == "malicious"


def test_attachment_internals(page, server, tmp_path):
    base = server()
    open_app(page, base)
    msg = samples.message_with([("Invoice.docm", "application/octet-stream", samples.malicious_docm()),
                                ("scan.pdf", "application/pdf", samples.malicious_pdf()),
                                ("photo.lnk", "application/octet-stream", samples.malicious_lnk()),
                                ("notes.one", "application/octet-stream", samples.malicious_onenote()),
                                ("Invoice.zip", "application/zip", samples.make_zip({"a/invoice.pdf.exe": samples.fake_pe()}))])
    upload(page, tmp_path, {"attachments.eml": msg})
    page.locator(".hero").wait_for()
    body = tab(page, "Attachments")
    assert page.locator(".att").count() == 5
    text = body.text_content()
    for expected in ["VBA macro · Module1", "auto-run: AutoOpen", "DDE fields", "Embedded objects", "External references",
                     "JavaScript", "Launch", "Windows shortcut", "powershell", "Archive contents", "invoice.pdf.exe",
                     "SHA256", "Document metadata", "Jane Attacker"]:
        assert expected.lower() in text.lower(), expected
    assert page.locator(".att .finding").count() >= 10


def test_nested_message_drill_down(page, server, tmp_path):
    base = server()
    open_app(page, base)
    upload(page, tmp_path, {"forwarded.eml": samples.forwarded_eml()})
    page.locator(".hero").wait_for()
    outer = page.locator(".hero-subject").text_content()
    tab(page, "Attached emails")
    page.locator(".nested-item").first.click()
    inner = page.locator(".hero-subject").text_content()
    assert inner != outer and page.locator(".crumbs").count() == 1
    page.locator(".crumbs button", has_text="Original message").click()
    assert page.locator(".hero-subject").text_content() == outer and page.locator(".crumbs").count() == 0


def test_authentication_with_dns(page, server, tmp_path):
    from email_forensics.resolver import RecordingResolver, ReplayResolver

    resolver = RecordingResolver(ReplayResolver(FIX / "dkim" / "dns.json"))
    base = server(options=AnalysisOptions(resolver=resolver))
    open_app(page, base)
    assert page.locator(".chip.on", has_text="DNS checks on").count() == 1
    upload(page, tmp_path, {"arc.eml": (FIX / "dkim" / "arc_two_hops.eml").read_bytes()})
    page.locator(".hero").wait_for()
    text = tab(page, "Authentication").text_content()
    assert "DKIM · signer.test" in text and "ARC · 2 hop(s)" in text and "Offline mode" not in text
    assert page.locator("#tab-body .auth-card .res-pass").count() >= 2


# --------------------------------------------------------------------------- exports and tools


def test_downloads(page, server, tmp_path):
    base = server()
    open_app(page, base)
    upload(page, tmp_path, {UNICODE_NAME: PHISH})
    page.locator(".hero").wait_for()

    def grab(click):
        with page.expect_download() as info:
            click()
        d = info.value
        return d.suggested_filename, Path(d.path()).read_text(encoding="utf-8")

    name, html = grab(lambda: page.locator(".btn.primary", has_text="HTML report").click())
    assert name.endswith("-report.html") and "<!doctype html>" in html.lower() and "default-src 'none'" in html
    for fmt, check in [("STIX", lambda t: json.loads(t)["type"] == "bundle"),
                       ("MISP", lambda t: json.loads(t)["Event"]["Attribute"]),
                       ("CSV", lambda t: list(csv.DictReader(io.StringIO(t)))[0]["type"])]:
        page.locator(".btn", has_text="Export indicators").click()
        name, text = grab(lambda: page.locator(".menu-list button", has_text=fmt).click())
        assert check(text), fmt
        assert page.locator(".menu-list").is_hidden()
    name, text = grab(lambda: page.locator(".btn", has_text="JSON").click())
    assert name.endswith("-report.json") and json.loads(text)["evidence"]["sha256"]


def test_copy_buttons(browser, server, tmp_path):
    base = server()
    ctx = browser.new_context(permissions=["clipboard-read", "clipboard-write"])
    pg = ctx.new_page()
    open_app(pg, base)
    upload(pg, tmp_path, {"p.eml": PHISH})
    pg.locator(".hero").wait_for()
    pg.locator(".hero .copy").click()
    sha = pg.evaluate("navigator.clipboard.readText()")
    assert len(sha) == 64 and sha in pg.locator(".hero").text_content()
    assert pg.locator("#toast.show", has_text="Copied").count() == 1
    tab(pg, "Links & content")
    pg.locator("#tab-body .copy").first.click()
    assert pg.evaluate("navigator.clipboard.readText()").startswith(("http", "javascript"))  # the real URL, not defanged
    ctx.close()


def test_theme_toggle_persists(page, server):
    base = server()
    open_app(page, base)
    before = page.evaluate("getComputedStyle(document.body).backgroundColor")
    page.click("#theme-toggle")
    theme = page.evaluate("document.documentElement.dataset.theme")
    assert theme in ("dark", "light")
    assert page.evaluate("getComputedStyle(document.body).backgroundColor") != before
    page.reload()
    page.locator("#version", has_text="v1").wait_for()
    assert page.evaluate("document.documentElement.dataset.theme") == theme


def test_clear_history(page, server, tmp_path):
    base = server()
    open_app(page, base)
    upload(page, tmp_path, {"a.eml": PHISH, "b.eml": LEGIT})
    wait_done(page, 2)
    page.click("#clear-history")
    assert page.locator(".history-item").count() == 0 and page.locator("#welcome").is_visible()
    assert page.locator("#clear-history").is_hidden()


# --------------------------------------------------------------------------- errors and access control


def test_token_flow_and_retry(page, server, tmp_path):
    base = server(token=TOKEN)
    open_app(page, base)
    assert page.locator("#token-box").is_visible()
    upload(page, tmp_path, {"p.eml": PHISH})
    page.locator(".history-item.failed").wait_for()
    assert "token" in page.locator("#report").text_content().lower()
    page.fill("#token-input", "wrong-token-but-long-enough")
    page.click("text=Retry")
    page.locator(".history-item.failed").wait_for()
    page.fill("#token-input", TOKEN)
    page.click("text=Retry")
    page.locator(".hero").wait_for()
    assert page.locator(".history-item.failed").count() == 0
    # exports send the token too
    with page.expect_download():
        page.locator(".btn.primary", has_text="HTML report").click()


def test_bad_and_oversized_files(page, server, tmp_path):
    base = server(max_upload=4000)
    open_app(page, base)
    upload(page, tmp_path, {"not-mail.msg": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600})
    page.locator(".history-item.failed").wait_for()
    assert "not an Outlook message" in page.locator("#report").text_content()
    assert page.locator("text=Retry").count() == 1
    upload(page, tmp_path, {"huge.eml": PHISH + b"x" * 5000})
    page.locator(".history-item.failed", has_text="huge.eml").click()
    assert "larger than this server accepts" in page.locator("#report").text_content()
    assert page.locator("text=Retry").count() == 0  # resending cannot help


def test_hostile_content_is_inert(page, server, tmp_path):
    base = server()
    open_app(page, base)
    evil = (b'From: "<img src=x onerror=alert(1)>" <a@evil.test>\r\nTo: b@x.test\r\n'
            b"Subject: <script>alert(2)</script><img src=x onerror=alert(3)>\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n'
            b'<a href="javascript:alert(4)">"><svg onload=alert(5)></a>\r\n--b\r\n'
            b'Content-Type: application/octet-stream; name="<img src=x onerror=alert(6)>.exe"\r\n'
            b"Content-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAAEAAAA\r\n--b--\r\n")
    upload(page, tmp_path, {"<img src=x onerror=alert(7)>.eml": evil})
    page.locator(".hero").wait_for()
    for name in ["Findings", "Sender & route", "Authentication", "Links & content", "Attachments", "Indicators", "Raw JSON"]:
        tab(page, name)
        page.locator(".finding summary").first.click() if name == "Findings" else None
    assert page.locator(".hero-subject").text_content() == "<script>alert(2)</script><img src=x onerror=alert(3)>"
    assert page.locator("#report img, #report script, #history img, #report svg[onload]").count() == 0
    # the fixture fails the test if any alert() dialog opened


def test_works_without_javascript(browser, server, tmp_path):
    base = server()
    ctx = browser.new_context(java_script_enabled=False)
    pg = ctx.new_page()
    pg.goto(base)
    path = tmp_path / "p.eml"
    path.write_bytes(PHISH)
    pg.set_input_files("noscript form input[type=file]", str(path))
    pg.click("noscript form button[type=submit]")
    pg.wait_for_load_state()
    assert "MALICIOUS" in pg.content().upper() and "secure-paypa1" in pg.content()
    ctx.close()


def test_phone_layout(browser, server, tmp_path):
    base = server()
    ctx = browser.new_context(viewport={"width": 375, "height": 740}, is_mobile=True, has_touch=True)
    pg = ctx.new_page()
    open_app(pg, base)
    upload(pg, tmp_path, {"p.eml": PHISH, "att.eml": samples.message_with([("Invoice.docm", "application/octet-stream", samples.malicious_docm())])})
    wait_done(pg, 2)
    for name in ["Findings", "Sender & route", "Links & content", "Attachments", "Indicators", "Raw JSON"]:
        tab(pg, name)
        assert pg.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth") <= 0, name
    ctx.close()
