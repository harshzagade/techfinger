from techfinger.fingerprint import confidence_level, fingerprint
from techfinger.rules import RULES


def _by_name(detections, name):
    return [d for d in detections if d.name == name]


def test_wordpress_full_detection():
    headers = {"server": "nginx/1.24.0", "content-type": "text/html"}
    body = ('<meta name="generator" content="WordPress 6.4.2">'
            '<link href="/wp-content/themes/x/style.css">'
            '<script src="/wp-includes/js/jquery.js"></script>')
    dets = fingerprint(headers, body)
    wp = _by_name(dets, "WordPress")
    assert len(wp) == 1
    assert wp[0].version == "6.4.2"
    assert wp[0].confidence == 100  # 60 + 40 + 40, capped
    assert wp[0].level == "High"
    assert any("generator" in e for e in wp[0].evidence)
    # nginx from the Server header is a separate detection
    assert _by_name(dets, "Nginx")[0].version == "1.24.0"


def test_header_matching_is_case_insensitive():
    dets = fingerprint({"X-Powered-By": "Express"}, "<html></html>")
    assert _by_name(dets, "Express")[0].confidence == 60
    assert _by_name(dets, "Node.js")  # Express implies Node.js


def test_cookie_rules_match_set_cookie_header():
    dets = fingerprint({"set-cookie": "csrftoken=abc; Path=/"},
                       "<html></html>")
    assert _by_name(dets, "Django")[0].level == "Medium"


def test_script_src_rules_match_only_src_urls():
    # "jquery" in body text alone is a weak html hint; the script rule
    # needs an actual <script src>.
    dets = fingerprint({}, '<script src="/js/jquery.min.js"></script>')
    jq = _by_name(dets, "jQuery")[0]
    assert jq.confidence == 40


def test_meta_tag_with_content_before_name():
    body = ('<meta content="WordPress 6.5" name="generator">')
    dets = fingerprint({}, body)
    wp = _by_name(dets, "WordPress")[0]
    assert wp.version == "6.5"


def test_plain_page_detects_nothing():
    dets = fingerprint({"server": "unknown"}, "<html><body>hi</body></html>")
    assert dets == []


def test_confidence_levels():
    assert confidence_level(100) == "High"
    assert confidence_level(70) == "High"
    assert confidence_level(69) == "Medium"
    assert confidence_level(40) == "Medium"
    assert confidence_level(39) == "Low"


def test_detections_sorted_by_confidence_desc():
    headers = {"x-powered-by": "Express", "server": "nginx/1.24.0"}
    body = '<meta name="generator" content="WordPress 6.4.2">'
    dets = fingerprint(headers, body)
    scores = [d.confidence for d in dets]
    assert scores == sorted(scores, reverse=True)
    assert dets[0].name in ("WordPress", "Express", "Node.js")


def test_version_comes_from_first_matching_rule():
    # Angular ng-version captures the version; the ng-app rule has none.
    body = '<html ng-app="x" ng-version="17.2.0"></html>'
    dets = fingerprint({}, body)
    ang = _by_name(dets, "Angular")[0]
    assert ang.version == "17.2.0"


def test_custom_technology_via_merged_rules():
    from techfinger.rules import Technology, Rule
    custom = [Technology("MyCMS", "CMS",
                         [Rule("html", r"mycms", 60, "mycms marker")])]
    dets = fingerprint({}, "<html>mycms inside</html>", technologies=custom)
    assert len(dets) == 1
    assert dets[0].name == "MyCMS"


def test_builtin_rule_count_unchanged():
    # Guard against accidental rule loss when editing rules.py.
    assert len(RULES) >= 25
