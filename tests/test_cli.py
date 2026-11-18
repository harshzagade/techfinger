import json

import pytest

from techfinger.cli import main


def test_cli_text_output(fixture_server, capsys):
    assert main([f"{fixture_server}/wordpress"]) == 0
    out = capsys.readouterr().out
    assert "TechFinger report for" in out
    assert "WordPress 6.4.2 (CMS)" in out
    assert "[HIGH 100]" in out
    assert "Nginx 1.24.0 (Web server)" in out


def test_cli_json_output(fixture_server, capsys):
    assert main([f"{fixture_server}/next", "--json"]) == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["status"] == 200
    assert data["url"].endswith("/next")
    tech = {t["name"]: t for t in data["technologies"]}
    assert tech["Next.js"]["confidence"] == 100
    assert tech["Next.js"]["level"] == "High"
    assert tech["Next.js"]["evidence"]


def test_cli_plain_page_reports_none(fixture_server, capsys):
    assert main([f"{fixture_server}/plain"]) == 0
    out = capsys.readouterr().out
    assert "No known technologies detected." in out


def test_cli_list(capsys):
    assert main(["--list"]) == 0
    out = capsys.readouterr().out
    assert "WordPress (CMS)" in out
    assert "Nginx (Web server)" in out
    assert len(out.strip().splitlines()) >= 25


def test_cli_missing_url_exits_2(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_cli_bad_timeout_exits_2(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["http://127.0.0.1:1/", "--timeout", "0"])
    assert exc.value.code == 2


def test_cli_bad_rules_file_exits_2(tmp_path, capsys):
    bad = tmp_path / "rules.json"
    bad.write_text("{nope")
    assert main(["http://127.0.0.1:1/", "--rules", str(bad)]) == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_cli_fetch_failure_exits_1(capsys):
    assert main(["http://127.0.0.1:1/"]) == 1
    assert "fetch failed" in capsys.readouterr().err


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "techfinger" in capsys.readouterr().out
