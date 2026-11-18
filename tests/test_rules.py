import json

import pytest

from techfinger.rules import (
    RULES,
    Rule,
    list_technologies,
    load_rules_file,
    merged_rules,
)


def test_builtin_rule_set_is_nonempty_and_valid():
    assert len(RULES) >= 25
    names = [t.name for t in RULES]
    assert len(names) == len(set(names))  # no duplicate technology names
    for tech in RULES:
        assert tech.rules, f"{tech.name} has no rules"


def test_rule_rejects_bad_kind():
    with pytest.raises(ValueError, match="unknown rule kind"):
        Rule("bogus", r"x", 10, "bad kind")


def test_rule_rejects_bad_weight():
    with pytest.raises(ValueError, match="weight"):
        Rule("html", r"x", 0, "zero weight")
    with pytest.raises(ValueError, match="weight"):
        Rule("html", r"x", 101, "overweight")


def test_rule_rejects_bad_regex():
    with pytest.raises(Exception):
        Rule("html", r"([", 10, "unbalanced")


def test_list_technologies_sorted_and_known():
    listed = list_technologies()
    assert ("WordPress", "CMS") in listed
    assert ("Next.js", "Framework") in listed
    assert ("Nginx", "Web server") in listed
    assert listed == sorted(listed)


def test_load_rules_file_adds_new_technology(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"technologies": [
        {"name": "MyCMS", "category": "CMS", "rules": [
            {"kind": "html", "pattern": "mycms", "weight": 60,
             "description": "mycms marker"}]}]}))
    loaded = load_rules_file(str(path))
    assert len(loaded) == 1
    assert loaded[0].name == "MyCMS"
    assert loaded[0].rules[0].pattern == "mycms"


def test_load_rules_file_overrides_builtin(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"technologies": [
        {"name": "WordPress", "category": "CMS", "rules": [
            {"kind": "html", "pattern": "totally-custom", "weight": 60,
             "description": "custom"}]}]}))
    merged = merged_rules(str(path))
    wp = [t for t in merged if t.name == "WordPress"][0]
    assert len(wp.rules) == 1
    assert wp.rules[0].pattern == "totally-custom"
    # everything else is untouched
    assert len(merged) == len(RULES)


def test_load_rules_file_rejects_bad_json(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_rules_file(str(path))


def test_load_rules_file_rejects_missing_file():
    with pytest.raises(ValueError, match="cannot read"):
        load_rules_file("/nonexistent/rules.json")


def test_load_rules_file_rejects_bad_rule(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"technologies": [
        {"name": "Bad", "category": "CMS", "rules": [
            {"kind": "nope", "pattern": "x", "weight": 10}]}]}))
    with pytest.raises(ValueError, match="bad rule"):
        load_rules_file(str(path))


def test_rule_set_has_150_technologies():
    assert len(RULES) >= 150

def test_no_duplicate_technology_names():
    names = [t.name for t in RULES]
    assert len(set(names)) == len(names), f"Duplicate technologies found: {[n for n in names if names.count(n) > 1]}"

def test_every_technology_has_a_strong_rule():
    import re
    for tech in RULES:
        assert any(r.weight >= 40 for r in tech.rules), f"{tech.name} has no strong rules (weight >= 40)"
        for rule in tech.rules:
            assert 1 <= rule.weight <= 100
            re.compile(rule.pattern, re.IGNORECASE)
            if rule.kind == "path":
                assert rule.path is not None
                assert rule.path.startswith("/")
                assert " 200 " in rule.pattern
            else:
                assert rule.path is None
