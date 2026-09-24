import json

from email_forensics.cli import main


def test_cli_json_output(fixture_path, capsys):
    assert main(["analyze", "--json", str(fixture_path("legit.eml"))]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["evidence"]["sha256"]) == 64
    assert data["headers"]["from_address"] == "alice@example.com"
    assert len(data["headers"]["hops"]) == 2


def test_cli_min_severity_filters(fixture_path, capsys):
    main(["analyze", "--json", "--min-severity", "high", str(fixture_path("bec_spoof.eml"))])
    data = json.loads(capsys.readouterr().out)
    assert {f["severity"] for f in data["findings"]} == {"high"}


def test_cli_missing_file(capsys):
    assert main(["analyze", "/nonexistent.eml"]) == 2
    assert "not a file" in capsys.readouterr().err
