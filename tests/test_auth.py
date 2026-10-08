import json
from pathlib import Path

from email_forensics.analyzer import analyze_file
from email_forensics.auth import spf_inputs
from email_forensics.cli import main
from email_forensics.headers import analyze_headers
from email_forensics.loader import parse_bytes
from email_forensics.resolver import RecordingResolver, ReplayResolver
from fakedns import FakeResolver

DKIM = Path(__file__).parent / "fixtures" / "dkim"


def codes(report):
    return {f.code for f in report.findings}


def test_offline_by_default(fixture_path):
    report = analyze_file(DKIM / "rsa_relaxed.eml")
    assert not report.auth.online and report.auth.dkim[0].result == "neutral"
    assert "AUTHV_OFFLINE" in codes(report)


def test_offline_detects_body_modification(tmp_path):
    raw = (DKIM / "rsa_relaxed.eml").read_bytes().replace(b"numbers\tare", b"numbers are NOT")
    path = tmp_path / "x.eml"
    path.write_bytes(raw)
    assert "AUTHV_DKIM_BODY_MODIFIED" in codes(analyze_file(path))


def test_online_with_replay_and_full_policy(tmp_path):
    lookups = json.loads((DKIM / "dns.json").read_text())["lookups"]
    records = {(lk["name"], "TXT"): lk["answers"] for lk in lookups}
    records[("signer.test", "TXT")] = ["v=spf1 ip4:192.0.2.0/24 -all"]
    records[("_dmarc.signer.test", "TXT")] = ["v=DMARC1; p=reject"]
    raw = b"Return-Path: <bounce@signer.test>\r\n" + (DKIM / "rsa_relaxed.eml").read_bytes()
    path = tmp_path / "m.eml"
    path.write_bytes(raw)
    report = analyze_file(path, resolver=RecordingResolver(FakeResolver(records)), spf_ip="192.0.2.5")
    assert {"AUTHV_DKIM_PASS", "AUTHV_SPF_PASS", "AUTHV_DMARC_PASS"} <= codes(report)
    assert report.auth.spf_ip_source == "--spf-ip"
    assert len(report.auth.dns_lookups) >= 3

    spoof = analyze_file(path, resolver=RecordingResolver(FakeResolver(records)), spf_ip="203.0.113.66")
    assert "AUTHV_SPF_FAIL" in codes(spoof) and "AUTHV_DMARC_PASS" in codes(spoof)  # DKIM still aligns


def test_mismatch_with_receiver_verdict(tmp_path):
    raw = (b"Authentication-Results: mx.receiver.test; dkim=pass header.d=signer.test\r\n"
           + (DKIM / "rsa_relaxed.eml").read_bytes().replace(b"Subject: Quarterly", b"Subject: Changed"))
    path = tmp_path / "m.eml"
    path.write_bytes(raw)
    report = analyze_file(path, resolver=RecordingResolver(ReplayResolver(DKIM / "dns.json")))
    mismatch = [f for f in report.findings if f.code == "AUTHV_MISMATCH"]
    assert mismatch and mismatch[0].severity.value == "high"
    assert "AUTHV_DKIM_FAIL" in codes(report)


def test_length_tag_with_appended_content(tmp_path):
    path = tmp_path / "m.eml"
    path.write_bytes((DKIM / "rsa_sha1_length.eml").read_bytes() + b"Pay to IBAN XX00 now\r\n")
    report = analyze_file(path, resolver=RecordingResolver(ReplayResolver(DKIM / "dns.json")))
    assert {"AUTHV_DKIM_UNSIGNED_CONTENT", "AUTHV_DKIM_SHA1", "AUTHV_DKIM_TESTING", "AUTHV_DKIM_WEAK_KEY"} <= codes(report)


def test_arc_reported(fixture_path):
    report = analyze_file(DKIM / "arc_two_hops.eml", resolver=RecordingResolver(ReplayResolver(DKIM / "dns.json")))
    assert "AUTHV_ARC_PASS" in codes(report) and report.auth.arc.instances == 2


def test_spf_inputs_priority():
    msg = parse_bytes(
        b"Received-SPF: Pass (mx: domain of a@example.com designates 192.0.2.7 as permitted sender) "
        b"client-ip=192.0.2.7; envelope-from=a@example.com; helo=out.example.com;\n"
        b"Return-Path: <other@x.test>\nFrom: a@example.com\n\nbody\n")
    ip, source, mail_from, helo = spf_inputs(msg, analyze_headers(msg))
    assert (ip, source, mail_from, helo) == ("192.0.2.7", "Received-SPF client-ip", "a@example.com", "out.example.com")

    msg = parse_bytes(
        b"Authentication-Results: mx.google.com; spf=pass (google.com: domain of a@example.com designates "
        b"2001:db8::5 as permitted sender) smtp.mailfrom=example.com\nFrom: a@example.com\n\nbody\n")
    ip, source, mail_from, _ = spf_inputs(msg, analyze_headers(msg))
    assert (ip, source, mail_from) == ("2001:db8::5", "Authentication-Results comment", "postmaster@example.com")

    msg = parse_bytes(
        b"Received: from mail.internal.example.org (mail.internal.example.org [10.0.0.5]) by mx2.example.org; "
        b"Tue, 22 Sep 2026 10:00:09 +0000\n"
        b"Received: from out.sender.test (out.sender.test [81.2.69.160]) by mx1.example.org; "
        b"Tue, 22 Sep 2026 10:00:05 +0000\n"
        b"Return-Path: <a@sender.test>\nFrom: a@sender.test\n\nbody\n")
    ip, source, mail_from, helo = spf_inputs(msg, analyze_headers(msg))
    assert ip == "81.2.69.160" and "heuristic" in source and helo == "out.sender.test"


def test_cli_record_and_replay(tmp_path, capsys):
    rec = tmp_path / "dns.json"
    assert main(["analyze", "--json", "--dns-replay", str(DKIM / "dns.json"), "--dns-record", str(rec),
                 str(DKIM / "ed25519.eml")]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["auth"]["dkim"][0]["result"] == "pass" and data["auth"]["online"]
    saved = json.loads(rec.read_text())["lookups"]
    assert any(lk["name"] == "ed._domainkey.signer.test" and lk["answers"] for lk in saved)
    # The recording alone reproduces the verdict.
    assert main(["analyze", "--json", "--dns-replay", str(rec), str(DKIM / "ed25519.eml")]) == 0
    assert json.loads(capsys.readouterr().out)["auth"]["dkim"][0]["result"] == "pass"


def test_cli_resolver_errors(capsys, fixture_path):
    assert main(["analyze", "--online", "--doh", str(fixture_path("legit.eml"))]) == 2
    assert main(["analyze", "--online", "--doh-url", "https://dns.example/resolve", str(fixture_path("legit.eml"))]) == 2
    assert main(["analyze", "--dns-record", "x.json", str(fixture_path("legit.eml"))]) == 2
    assert main(["analyze", "--dns-replay", "/nonexistent.json", str(fixture_path("legit.eml"))]) == 2
