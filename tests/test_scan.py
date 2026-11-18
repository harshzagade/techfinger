"""Tests for the scanning engine and new detection surfaces."""

import hashlib
import json
import pathlib
import pytest

from techfinger.scan import scan_url, favicon_hash
from techfinger.rules import Rule, Technology
from techfinger.cli import main

def test_favicon_hash_calculation():
    data = b"FAKE-FAVICON-BYTES-1234"
    expected = hashlib.sha256(data).hexdigest()[:16]
    assert favicon_hash(data) == expected

def test_scan_jquery_assets(fixture_server):
    res = scan_url(f"{fixture_server}/jquery-page")
    # Detects jQuery from script tag (confidence 40) + JS content (confidence 60)
    jquery_det = next(d for d in res.detections if d.name == "jQuery")
    assert jquery_det.version == "3.7.1"
    assert any("jQuery version banner" in e for e in jquery_det.evidence)

    # Asset URL filtering
    assert any(u.endswith("/static/jquery.min.js") for u in res.asset_urls)
    assert not any("evil.js" in u for u in res.asset_urls)

def test_scan_bootstrap_assets(fixture_server):
    res = scan_url(f"{fixture_server}/bootstrap-page")
    bootstrap_det = next(d for d in res.detections if d.name == "Bootstrap")
    assert bootstrap_det.version == "5.3.3"

def test_scan_wordpress_path_probes(fixture_server, fixture_probe_server):
    # On normal server, probes 404, no WordPress
    res_normal = scan_url(f"{fixture_server}/bare-wp")
    assert not any(d.name == "WordPress" for d in res_normal.detections)

    # On probe server, probes 200, WordPress detected
    res_probe = scan_url(f"{fixture_probe_server}/bare-wp")
    wp_det = next(d for d in res_probe.detections if d.name == "WordPress")
    assert any("wp-json API responds" in e for e in wp_det.evidence)

def test_scan_joomla_path_probes(fixture_probe_server):
    res = scan_url(f"{fixture_probe_server}/bare-joomla")
    joomla_det = next(d for d in res.detections if d.name == "Joomla")
    assert any("administrator login page" in e for e in joomla_det.evidence)

def test_scan_plain_regression(fixture_server):
    res = scan_url(f"{fixture_server}/plain")
    assert res.detections == []
    # But favicon is still hashed if it exists on the server
    assert res.favicon_hash == favicon_hash(b"FAKE-FAVICON-BYTES-1234")

def test_scan_disable_favicon(fixture_server):
    res = scan_url(f"{fixture_server}/plain", enable_favicon=False)
    assert res.favicon_hash is None

def test_scan_disable_assets(fixture_server):
    res = scan_url(f"{fixture_server}/jquery-page", enable_assets=False)
    jquery_det = next(d for d in res.detections if d.name == "jQuery")
    # Detected via script tag rule (kind: script), but no version from JS content
    assert jquery_det.version is None
    assert res.asset_urls == []

def test_scan_disable_paths(fixture_probe_server):
    res = scan_url(f"{fixture_probe_server}/bare-wp", enable_paths=False)
    assert not any(d.name == "WordPress" for d in res.detections)
    assert res.probes == {}

def test_cli_json_and_flags(fixture_server, capsys):
    url = f"{fixture_server}/jquery-page"

    # Standard run
    assert main([url, "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["favicon_hash"] == favicon_hash(b"FAKE-FAVICON-BYTES-1234")
    assert isinstance(out["probed_paths"], list)

    # No favicon
    assert main([url, "--json", "--no-favicon"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["favicon_hash"] is None

    # No paths
    assert main([url, "--json", "--no-paths"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["probed_paths"] == []

def test_custom_favicon_rule(fixture_server, tmp_path, capsys):
    hash_val = favicon_hash(b"FAKE-FAVICON-BYTES-1234")
    rules_file = tmp_path / "rules.json"
    rules_data = {"technologies": [
        {
            "name": "FaviCMS",
            "category": "CMS",
            "rules": [
                {"kind": "favicon", "pattern": hash_val, "weight": 100, "description": "match favicon"}
            ]
        }
    ]}
    rules_file.write_text(json.dumps(rules_data))

    assert main([f"{fixture_server}/plain", "--rules", str(rules_file), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert any(d["name"] == "FaviCMS" for d in out["technologies"])

def test_rule_validation():
    # Missing path for kind 'path'
    with pytest.raises(ValueError, match="requires a path"):
        Rule(kind="path", pattern="x", weight=40, description="d")

    # Path provided for non-path kind
    with pytest.raises(ValueError, match="cannot have a path"):
        Rule(kind="html", pattern="x", weight=40, description="d", path="/x")

def test_fetch_failure_tolerance(fixture_server):
    # Ensure scanning continues and finds detections even if extra fetches might fail
    # /redirect returns 302 to /wordpress which has detections.
    res = scan_url(f"{fixture_server}/redirect")
    assert any(d.name == "WordPress" for d in res.detections)
    assert res.status == 200
    assert res.final_url.endswith("/wordpress")
