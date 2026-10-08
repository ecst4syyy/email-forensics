import pytest

from email_forensics.analyzer import analyze_file
from email_forensics.attachments import analyze_attachments
from email_forensics.lnk import parse_lnk
from email_forensics.loader import parse_bytes
from email_forensics.mime import walk_mime
from email_forensics.scripts import analyze_script
import samples as s


def run(name, ctype, data):
    atts, findings = analyze_attachments(walk_mime(parse_bytes(s.message_with([(name, ctype, data)]))))
    return atts[0], {f.code: f for f in findings}


@pytest.mark.parametrize("name,ctype,builder,expected", [
    ("Invoice.doc", "application/msword", s.malicious_doc,
     {"MACRO_MALICIOUS_PATTERN", "DOC_EMBEDDED_OBJECT", "DOC_METADATA"}),
    ("Invoice.docm", "application/vnd.ms-word.document.macroEnabled.12", s.malicious_docm,
     {"MACRO_MALICIOUS_PATTERN", "DOC_DDE", "DOC_EXTERNAL_OBJECT", "DOC_ACTIVEX", "DOC_EMBEDDED_OBJECT",
      "DOC_UNC_PATH", "DOC_REMOTE_IMAGE"}),
    ("Report.xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", s.xlm_workbook, {"MACRO_XLM"}),
    ("Scan.rtf", "application/rtf", s.equation_rtf, {"RTF_EXPLOIT_CLASS", "DOC_EMBEDDED_OBJECT"}),
    ("Statement.pdf", "application/pdf", s.malicious_pdf,
     {"PDF_JAVASCRIPT", "PDF_LAUNCH", "PDF_EMBEDDED_FILE", "PDF_OBFUSCATED_NAMES", "PDF_LINKS"}),
    ("Invoice.pdf.lnk", "application/octet-stream", s.malicious_lnk,
     {"LNK_RUNS_COMMAND", "LNK_ICON_DISGUISE", "LNK_HIDDEN_WINDOW", "LNK_MACHINE_ID", "SCRIPT_ENCODED_COMMAND",
      "SCRIPT_DOWNLOADER"}),
    ("Notes.one", "application/octet-stream", s.malicious_onenote, {"ONENOTE_EMBEDDED_FILE"}),
])
def test_payload_findings(name, ctype, builder, expected):
    att, found = run(name, ctype, builder())
    assert expected <= set(found), sorted(found)
    assert att.payload is not None


def test_embedded_executable_is_high():
    _, found = run("Invoice.docm", "application/octet-stream", s.malicious_docm())
    assert found["DOC_EMBEDDED_OBJECT"].severity.value == "high"
    _, found = run("Notes.one", "application/octet-stream", s.malicious_onenote())
    assert found["ONENOTE_EMBEDDED_FILE"].severity.value == "high"


def test_payload_urls_reach_url_checks():
    att, found = run("Statement.pdf", "application/pdf", s.malicious_pdf())
    assert "https://paypa1-secure.test/login" in {u.url for u in att.urls}
    att, found = run("Invoice.docm", "application/octet-stream", s.malicious_docm())
    assert any("verify-account.test" in u.url for u in att.urls)
    assert "http://203.0.113.9/p.ps1" in {u.url for u in att.urls}  # from the VBA


@pytest.mark.parametrize("name,data,expected", [
    ("update.js", s.JS_DROPPER, {"SCRIPT_DOWNLOADER", "SCRIPT_OBFUSCATED"}),
    ("cleanup.bat", s.BAT_RANSOM, {"SCRIPT_RANSOMWARE", "SCRIPT_DEFENSE_EVASION"}),
    ("run.ps1", s.PS1_ENCODED, {"SCRIPT_ENCODED_COMMAND", "SCRIPT_DOWNLOADER", "SCRIPT_DEFENSE_EVASION"}),
])
def test_scripts(name, data, expected):
    _, found = run(name, "application/octet-stream", data)
    assert expected <= set(found), sorted(found)


def test_powershell_decoding():
    res = analyze_script(s.PS1_ENCODED.decode())
    assert res.decoded_commands == [s.POWERSHELL_STAGER]
    assert "http://203.0.113.9/stage2.ps1" in res.urls


def test_lnk_parser():
    info = parse_lnk(s.malicious_lnk())
    assert info.target.endswith("powershell.exe") and info.machine_id == "DESKTOP-ATTACK01"
    assert info.show_command.startswith("minimized") and "-Enc" in info.arguments
    assert parse_lnk(b"junk").error


def test_benign_documents_stay_quiet():
    _, found = run("report.pdf", "application/pdf", s.clean_pdf())
    assert set(found) == set()
    _, found = run("notes.txt", "text/plain", b"just text")
    assert set(found) == set()


def test_end_to_end_report_serialises(tmp_path):
    import json
    raw = s.message_with([("Invoice.docm", "application/octet-stream", s.malicious_docm()),
                          ("Statement.pdf", "application/pdf", s.malicious_pdf())])
    path = tmp_path / "m.eml"
    path.write_bytes(raw)
    report = analyze_file(path)
    data = json.loads(json.dumps(report.to_dict()))
    docm = data["attachments"][0]["payload"]
    assert docm["kind"] == "ooxml" and docm["office"]["vba"][0]["autoexec"] == ["AutoOpen"]
    assert data["attachments"][1]["payload"]["pdf"]["uris"]
